/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef WINDOWSFIREWALL_H
#define WINDOWSFIREWALL_H

#pragma comment(lib, "Fwpuclnt")

// Note: The windows.h import needs to come before the fwpmu.h import.
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
// clang-format on

#include <QByteArray>
#include <QHostAddress>
#include <QList>
#include <QMultiMap>
#include <QObject>
#include <QString>

#include "../client/daemon/interfaceconfig.h"

class IpAdressRange;
struct FWP_VALUE0_;
struct FWP_CONDITION_VALUE0_;

class WindowsFirewall final : public QObject {
 public:
  /**
   * @brief Opens the Windows Filtering Platform, initializes the session,
   * sublayer. Returns a WindowsFirewall object if successful, otherwise
   * nullptr. If there is already a WindowsFirewall object, it will be returned.
   *
   * @param parent - parent QObject
   * @return WindowsFirewall* - nullptr if failed to open the Windows Filtering
   * Platform.
   */
  static WindowsFirewall* create(QObject* parent);
  static bool removePersistentPolicy();
  ~WindowsFirewall() override;

  bool enableInterface(int vpnAdapterIndex);
  bool enableLanBypass(const QList<IPAddress>& ranges);
  bool enablePeerTraffic(const InterfaceConfig& config);
  bool blockIpv6TrafficForPeer(const QString& peer);
  bool disablePeerTraffic(const QString& pubkey);
  bool disableKillSwitch();
  bool allowAllTraffic();
  bool allowTrafficRange(const QStringList& ranges);

 private:
  using FilterIdList = QList<quint64>;

  static bool initSublayer();
  WindowsFirewall(HANDLE session, QObject* parent);
  HANDLE m_sessionHandle = INVALID_HANDLE_VALUE;
  quint64 m_vpnInterfaceLuid = 0;
  FilterIdList m_baseRules;
  FilterIdList m_strictRules;
  FilterIdList m_activationFenceRules;
  FilterIdList m_adapterRules;
  FilterIdList m_lanBypassRules;
  FilterIdList m_allowedRangeRules;
  FilterIdList m_orphanedRules;
  QMultiMap<QString, quint64> m_peerRules;
  QMultiMap<QString, quint64> m_ipv6BlockRules;
  bool m_policyStateKnown = false;

  bool allowTrafficForAppOnAll(const QString& exePath, int weight,
                               const QString& title, FilterIdList& target);
  bool blockTrafficTo(const QList<IPAddress>& range, uint8_t weight,
                      const QString& title, FilterIdList& target);
  bool blockTrafficTo(const IPAddress& addr, uint8_t weight,
                      const QString& title, FilterIdList& target);
  bool blockTrafficOnPort(uint port, uint8_t weight, const QString& title,
                          const GUID& subLayerKey, FilterIdList& target);
  bool allowTrafficTo(const IPAddress& addr, int weight, const QString& title,
                      FilterIdList& target);
  bool allowDnsTrafficTo(const QHostAddress& targetIP, uint port, int weight,
                         const QString& title, quint64 vpnInterfaceLuid,
                         FilterIdList& target);
  bool allowTrafficOfAdapter(quint64 networkAdapterLuid, uint8_t weight,
                             const QString& title, FilterIdList& target);
  bool allowDHCPTraffic(uint8_t weight, const QString& title,
                        FilterIdList& target);
  bool allowHyperVTraffic(uint8_t weight, const QString& title,
                          FilterIdList& target);
  bool allowLoopbackTraffic(uint8_t weight, const QString& title,
                            FilterIdList& target);

  // Utils
  QString getCurrentPath();
  void importAddress(const QHostAddress& addr, OUT FWP_VALUE0_& value,
                     OUT QByteArray* v6DataBuffer);
  void importAddress(const QHostAddress& addr, OUT FWP_CONDITION_VALUE0_& value,
                     OUT QByteArray* v6DataBuffer);
  bool enableFilter(FWPM_FILTER0* filter, const QString& title,
                    const QString& description, FilterIdList& target);
  bool enumerateProviderFilters(FilterIdList& filterIds);
  bool loadProviderFilters();
  bool reloadProviderState();
  void abortTransactionAndRecover();
  bool deleteFilters(const FilterIdList& filterIds);
  bool verifyTrackedProviderGeneration();
  FilterIdList allTrackedFilters() const;
};

#endif  // WINDOWSFIREWALL_H
