/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "linuxroutemonitor.h"

#include <QNetworkInterface>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QProcess>
#include <QScopeGuard>
#include <QTimer>

#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "core/utils/utilities.h"
#include "leakdetector.h"
#include "logger.h"
#include "core/utils/networkUtilities.h"

namespace {
Logger logger("LinuxRouteMonitor");
constexpr int NETLINK_ACK_TIMEOUT_MS = 1000;
}  // namespace


typedef struct wg_allowedip {
    uint16_t family;
    union {
        struct in_addr ip4;
        struct in6_addr ip6;
    };
    uint8_t cidr;
    struct wg_allowedip *next_allowedip;
} wg_allowedip;

constexpr const char* WG_INTERFACE = "amn0";

static void nlmsg_append_attr(struct nlmsghdr* nlmsg, size_t maxlen,
                              int attrtype, const void* attrdata,
                              size_t attrlen);
static void nlmsg_append_attr32(struct nlmsghdr* nlmsg, size_t maxlen,
                                int attrtype, uint32_t value);

static bool buildAllowedIp(wg_allowedip* ip, const IPAddress& prefix);


LinuxRouteMonitor::LinuxRouteMonitor(const QString& ifname, QObject* parent)
    : QObject(parent), m_ifname(ifname) {
  MZ_COUNT_CTOR(LinuxRouteMonitor);
  logger.debug() << "LinuxRouteMonitor created.";

  m_nlsock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (m_nlsock < 0) {
      logger.warning() << "Failed to create netlink socket:" << strerror(errno);
      return;
  }

  struct sockaddr_nl nladdr;
  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_pid = getpid();
  if (bind(m_nlsock, (struct sockaddr*)&nladdr, sizeof(nladdr)) != 0) {
      logger.warning() << "Failed to bind netlink socket:" << strerror(errno);
      close(m_nlsock);
      m_nlsock = -1;
      return;
  }

  m_notifier = new QSocketNotifier(m_nlsock, QSocketNotifier::Read, this);
  connect(m_notifier, &QSocketNotifier::activated, this,
          &LinuxRouteMonitor::nlsockReady);
}

LinuxRouteMonitor::~LinuxRouteMonitor() {
  MZ_COUNT_DTOR(LinuxRouteMonitor);
  if (m_nlsock >= 0) {
      close(m_nlsock);
      m_nlsock = -1;
  }
  logger.debug() << "WireguardUtilsLinux destroyed.";
}

// Compare memory against zero.
static int memcmpzero(const void* data, size_t len) {
  const quint8* ptr = static_cast<const quint8*>(data);
  while (len--) {
    if (*ptr++) return 1;
  }
  return 0;
}

bool LinuxRouteMonitor::insertRoute(const IPAddress& prefix) {
    logger.debug() << "Adding route to" << prefix.toString();

    const int flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    return rtmSendRoute(RTM_NEWROUTE, flags, RTN_UNICAST, prefix) ==
           EndpointRouteResult::Success;
}

bool LinuxRouteMonitor::deleteRoute(const IPAddress& prefix) {
    logger.debug() << "Removing route to" << prefix.toString();

    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    const EndpointRouteResult result =
        rtmSendRoute(RTM_DELROUTE, flags, RTN_UNICAST, prefix);
    return result == EndpointRouteResult::Success ||
           result == EndpointRouteResult::NotFound;
}

bool LinuxRouteMonitor::addExclusionRoute(const IPAddress& prefix) {
    logger.debug() << "Adding exclusion route for"
                   << prefix.toString();
    const int flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    return rtmSendRoute(RTM_NEWROUTE, flags, RTN_THROW, prefix) ==
           EndpointRouteResult::Success;
}

LinuxRouteMonitor::EndpointRouteResult
LinuxRouteMonitor::createEndpointRoute(const IPAddress& prefix) {
    logger.debug() << "Adding owned endpoint route for" << prefix.toString();
    if (prefix.type() != QAbstractSocket::IPv4Protocol) {
        logger.warning() << "Endpoint route requires an IPv4 prefix";
        return EndpointRouteResult::Failed;
    }
    const auto gatewayAndIface = NetworkUtilities::getGatewayAndIface();
    const QString gateway = gatewayAndIface.first;
    const QNetworkInterface interface = gatewayAndIface.second;
    struct in_addr gatewayAddress;
    if (gateway.isEmpty() || !interface.isValid() || interface.name().isEmpty() ||
        inet_pton(AF_INET, gateway.toUtf8().constData(), &gatewayAddress) != 1) {
        logger.warning() << "No valid IPv4 gateway interface for endpoint route";
        return EndpointRouteResult::Failed;
    }
    const unsigned int interfaceIndex =
        if_nametoindex(interface.name().toUtf8().constData());
    if (interfaceIndex == 0) {
        logger.warning() << "Endpoint gateway interface has no index"
                         << interface.name();
        return EndpointRouteResult::Failed;
    }
    const EndpointRouteReceipt receipt {gateway, interface.name(), interfaceIndex};
    const int flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    const EndpointRouteResult result =
        rtmSendRoute(RTM_NEWROUTE, flags, RTN_THROW, prefix, &receipt);
    if (result == EndpointRouteResult::Success) {
        m_ownedEndpointRoutes.insert(endpointRouteKey(prefix), receipt);
    }
    return result;
}

LinuxRouteMonitor::EndpointRouteResult
LinuxRouteMonitor::removeOwnedEndpointRoute(const IPAddress& prefix) {
    logger.debug() << "Removing owned endpoint route for"
                   << prefix.toString();
    const auto iterator = m_ownedEndpointRoutes.constFind(endpointRouteKey(prefix));
    if (iterator == m_ownedEndpointRoutes.constEnd()) {
        logger.warning() << "Refusing to remove endpoint route without ownership receipt"
                         << prefix.toString();
        return EndpointRouteResult::Uncertain;
    }
    const EndpointRouteReceipt& receipt = iterator.value();
    const QNetworkInterface interface =
        QNetworkInterface::interfaceFromName(receipt.interfaceName);
    if (!interface.isValid()) {
        logger.warning() << "Refusing to remove endpoint route: gateway interface is gone"
                         << receipt.interfaceName;
        return EndpointRouteResult::Uncertain;
    }
    const unsigned int currentInterfaceIndex =
        if_nametoindex(receipt.interfaceName.toUtf8().constData());
    if (currentInterfaceIndex == 0 || currentInterfaceIndex != receipt.interfaceIndex) {
        logger.warning() << "Refusing to remove endpoint route: gateway interface changed"
                         << receipt.interfaceName;
        return EndpointRouteResult::Uncertain;
    }
    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    const EndpointRouteResult result =
        rtmSendRoute(RTM_DELROUTE, flags, RTN_THROW, prefix, &receipt);
    if (result == EndpointRouteResult::Success ||
        result == EndpointRouteResult::NotFound) {
        m_ownedEndpointRoutes.remove(iterator.key());
    }
    return result;
}

bool LinuxRouteMonitor::deleteExclusionRoute(const IPAddress& prefix) {
    logger.debug() << "Removing exclusion route for" << prefix.toString();
    const int flags = NLM_F_REQUEST | NLM_F_ACK;
    const EndpointRouteResult result =
        rtmSendRoute(RTM_DELROUTE, flags, RTN_THROW, prefix);
    return result == EndpointRouteResult::Success ||
           result == EndpointRouteResult::NotFound;
}

LinuxRouteMonitor::EndpointRouteResult LinuxRouteMonitor::rtmSendRoute(
    int action, int flags, int type, const IPAddress& prefix,
    const EndpointRouteReceipt* endpointReceipt) {
    if (m_nlsock < 0) {
    logger.warning() << "Cannot modify route: netlink socket is unavailable";
    return EndpointRouteResult::Failed;
    }

    constexpr size_t rtm_max_size = sizeof(struct rtmsg) +
                                    2 * RTA_SPACE(sizeof(uint32_t)) +
                                    RTA_SPACE(sizeof(struct in6_addr));
    wg_allowedip ip;
    if (!buildAllowedIp(&ip, prefix)) {
    logger.warning() << "Invalid destination prefix";
    return EndpointRouteResult::Failed;
    }

    char buf[NLMSG_SPACE(rtm_max_size)];
    struct nlmsghdr* nlmsg = reinterpret_cast<struct nlmsghdr*>(buf);
    struct rtmsg* rtm = static_cast<struct rtmsg*>(NLMSG_DATA(nlmsg));

    memset(buf, 0, sizeof(buf));
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = action;
    nlmsg->nlmsg_flags = flags;
    nlmsg->nlmsg_pid = 0;
    nlmsg->nlmsg_seq = m_nlseq++;
    rtm->rtm_dst_len = ip.cidr;
    rtm->rtm_family = ip.family;
    rtm->rtm_type = type;
    rtm->rtm_table = endpointReceipt ? RT_TABLE_MAIN : RT_TABLE_UNSPEC;
    rtm->rtm_protocol = RTPROT_BOOT;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;

    if (rtm->rtm_family == AF_INET6) {
    nlmsg_append_attr(nlmsg, sizeof(buf), RTA_DST, &ip.ip6, sizeof(ip.ip6));
    } else {
    nlmsg_append_attr(nlmsg, sizeof(buf), RTA_DST, &ip.ip4, sizeof(ip.ip4));
    }

    if (rtm->rtm_type == RTN_UNICAST) {
    int index = if_nametoindex(WG_INTERFACE);

    if (index <= 0) {
        logger.error() << "if_nametoindex() failed:" << strerror(errno);
        return EndpointRouteResult::Failed;
    }
    nlmsg_append_attr32(nlmsg, sizeof(buf), RTA_OIF, index);
    nlmsg_append_attr32(nlmsg, sizeof(buf), RTA_PRIORITY, 1);
    }

    if (rtm->rtm_type == RTN_THROW) {
    const QString gateway = endpointReceipt
                                ? endpointReceipt->gateway
                                : NetworkUtilities::getGatewayAndIface().first;
    if (gateway.isEmpty()) {
        logger.warning() << "No default gateway available, skipping exclusion route";
        return EndpointRouteResult::Failed;
    }
    struct in_addr ip4;
    if (inet_pton(AF_INET, gateway.toUtf8().constData(), &ip4) != 1) {
        logger.warning() << "Invalid IPv4 gateway for exclusion route";
        return EndpointRouteResult::Failed;
    }
    nlmsg_append_attr(nlmsg, sizeof(buf), RTA_GATEWAY, &ip4, sizeof(ip4));
    nlmsg_append_attr32(nlmsg, sizeof(buf), RTA_PRIORITY, 0);
    if (endpointReceipt) {
        if (endpointReceipt->interfaceIndex == 0) {
            logger.warning() << "Endpoint route receipt has no interface index";
            return EndpointRouteResult::Failed;
        }
        nlmsg_append_attr32(nlmsg, sizeof(buf), RTA_OIF,
                            endpointReceipt->interfaceIndex);
    }
    rtm->rtm_type = RTN_UNICAST;
    }

    const int requestSocket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (requestSocket < 0) {
    logger.warning() << "Failed to create netlink request socket:" << strerror(errno);
    return EndpointRouteResult::Failed;
    }
    const auto requestSocketGuard = qScopeGuard([&] { close(requestSocket); });

    struct sockaddr_nl localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.nl_family = AF_NETLINK;
    if (bind(requestSocket, (struct sockaddr*)&localAddr, sizeof(localAddr)) != 0) {
    logger.warning() << "Failed to bind netlink request socket:" << strerror(errno);
    return EndpointRouteResult::Failed;
    }
    socklen_t localAddrLen = sizeof(localAddr);
    if (getsockname(requestSocket, (struct sockaddr*)&localAddr, &localAddrLen) != 0) {
    logger.warning() << "Failed to resolve netlink request port:" << strerror(errno);
    return EndpointRouteResult::Failed;
    }
    if (localAddrLen < sizeof(localAddr) || localAddr.nl_family != AF_NETLINK) {
    logger.warning() << "Netlink request socket returned an invalid address";
    return EndpointRouteResult::Failed;
    }
    if (localAddr.nl_pid == 0) {
    logger.warning() << "Netlink request socket has no assigned port";
    return EndpointRouteResult::Failed;
    }

    const uint32_t requestSequence = static_cast<uint32_t>(nlmsg->nlmsg_seq);
    nlmsg->nlmsg_pid = localAddr.nl_pid;
    struct sockaddr_nl kernelAddr;
    memset(&kernelAddr, 0, sizeof(kernelAddr));
    kernelAddr.nl_family = AF_NETLINK;
    const ssize_t sent = sendto(requestSocket, buf, nlmsg->nlmsg_len, MSG_DONTWAIT,
                                (struct sockaddr*)&kernelAddr, sizeof(kernelAddr));
    if (sent != static_cast<ssize_t>(nlmsg->nlmsg_len)) {
    logger.warning() << "Failed to send netlink route request:" << strerror(errno);
    return EndpointRouteResult::Uncertain;
    }

    QElapsedTimer ackTimer;
    ackTimer.start();
    struct pollfd pollFd { requestSocket, POLLIN, 0 };
    for (;;) {
    const qint64 elapsed = ackTimer.elapsed();
    const int remaining = NETLINK_ACK_TIMEOUT_MS - static_cast<int>(elapsed);
    if (remaining <= 0) {
        logger.warning() << "Timed out waiting for netlink route ACK";
        return EndpointRouteResult::Uncertain;
    }

    const int ready = poll(&pollFd, 1, remaining);
    if (ready < 0 && errno == EINTR) {
        continue;
    }
    if (ready < 0) {
        logger.warning() << "Failed waiting for netlink route ACK:" << strerror(errno);
        return EndpointRouteResult::Uncertain;
    }
    if (ready == 0) {
        logger.warning() << "Timed out waiting for netlink route ACK";
        return EndpointRouteResult::Uncertain;
    }
    if ((pollFd.revents & POLLNVAL) != 0 ||
        ((pollFd.revents & (POLLERR | POLLHUP)) != 0 &&
         (pollFd.revents & POLLIN) == 0)) {
        logger.warning() << "Netlink route request socket became invalid";
        return EndpointRouteResult::Uncertain;
    }

    char ackBuf[4096];
    struct sockaddr_nl peerAddr;
    memset(&peerAddr, 0, sizeof(peerAddr));
    socklen_t peerAddrLen = sizeof(peerAddr);
    const ssize_t received = recvfrom(requestSocket, ackBuf, sizeof(ackBuf), MSG_DONTWAIT,
                                      (struct sockaddr*)&peerAddr, &peerAddrLen);
    if (received < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
        }
        logger.warning() << "Failed to receive netlink route ACK:" << strerror(errno);
        return EndpointRouteResult::Uncertain;
    }
    if (peerAddrLen < sizeof(peerAddr) || peerAddr.nl_family != AF_NETLINK ||
        peerAddr.nl_pid != 0 || peerAddr.nl_groups != 0) {
        continue;
    }

    int messageLength = static_cast<int>(received);
    struct nlmsghdr* ack = reinterpret_cast<struct nlmsghdr*>(ackBuf);
    while (NLMSG_OK(ack, messageLength)) {
        if (ack->nlmsg_type == NLMSG_ERROR &&
            ack->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)) &&
            ack->nlmsg_pid == localAddr.nl_pid && ack->nlmsg_seq == requestSequence) {
        const struct nlmsgerr* error = static_cast<const struct nlmsgerr*>(NLMSG_DATA(ack));
        if (error->msg.nlmsg_type == static_cast<uint16_t>(action) &&
            error->msg.nlmsg_pid == localAddr.nl_pid &&
            error->msg.nlmsg_seq == requestSequence) {
            if (error->error == 0) {
            return EndpointRouteResult::Success;
            }
            logger.warning() << "Netlink route request failed:" << strerror(-error->error);
            if (error->error == -EEXIST) {
            return EndpointRouteResult::AlreadyExists;
            }
            if (error->error == -ENOENT) {
            return EndpointRouteResult::NotFound;
            }
            return EndpointRouteResult::Failed;
        }
        }
        ack = NLMSG_NEXT(ack, messageLength);
    }
    }
}

QString LinuxRouteMonitor::endpointRouteKey(const IPAddress& prefix) {
    return prefix.address().toString() + "/" +
           QString::number(prefix.prefixLength());
}

static void nlmsg_append_attr(struct nlmsghdr* nlmsg, size_t maxlen,
                              int attrtype, const void* attrdata,
                              size_t attrlen) {
    size_t newlen = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_SPACE(attrlen);
    if (newlen <= maxlen) {
    char* buf = reinterpret_cast<char*>(nlmsg) + NLMSG_ALIGN(nlmsg->nlmsg_len);
    struct rtattr* attr = reinterpret_cast<struct rtattr*>(buf);
    attr->rta_type = attrtype;
    attr->rta_len = RTA_LENGTH(attrlen);
    memcpy(RTA_DATA(attr), attrdata, attrlen);
    nlmsg->nlmsg_len = newlen;
    }
}

static void nlmsg_append_attr32(struct nlmsghdr* nlmsg, size_t maxlen,
                                int attrtype, uint32_t value) {
    nlmsg_append_attr(nlmsg, maxlen, attrtype, &value, sizeof(value));
}

void LinuxRouteMonitor::nlsockReady() {
    if (m_nlsock < 0) {
    return;
    }

    char buf[1024];
    ssize_t len = recv(m_nlsock, buf, sizeof(buf), MSG_DONTWAIT);
    if (len <= 0) {
    return;
    }

    struct nlmsghdr* nlmsg = (struct nlmsghdr*)buf;
    while (NLMSG_OK(nlmsg, len)) {
    if (nlmsg->nlmsg_type == NLMSG_DONE) {
        return;
    }
    if (nlmsg->nlmsg_type != NLMSG_ERROR) {
        nlmsg = NLMSG_NEXT(nlmsg, len);
        continue;
    }
    struct nlmsgerr* err = static_cast<struct nlmsgerr*>(NLMSG_DATA(nlmsg));
    if (err->error != 0) {
        logger.debug() << "Netlink request failed:" << strerror(-err->error);
    }
    nlmsg = NLMSG_NEXT(nlmsg, len);
    }
}

static bool buildAllowedIp(wg_allowedip* ip,
                                         const IPAddress& prefix) {
    const QByteArray addrString = prefix.address().toString().toUtf8();
    if (prefix.type() == QAbstractSocket::IPv4Protocol) {
    ip->family = AF_INET;
    ip->cidr = prefix.prefixLength();
    return inet_pton(AF_INET, addrString.constData(), &ip->ip4) == 1;
    }
    if (prefix.type() == QAbstractSocket::IPv6Protocol) {
    ip->family = AF_INET6;
    ip->cidr = prefix.prefixLength();
    return inet_pton(AF_INET6, addrString.constData(), &ip->ip6) == 1;
    }
    return false;
}
