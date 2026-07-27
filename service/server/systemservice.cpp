#include "version.h"
#include "localserver.h"
#include "logger.h"
#include "systemservice.h"


SystemService::SystemService(int argc, char **argv)
    : QtService<QCoreApplication>(argc, argv, SERVICE_NAME)
{
    setServiceDescription("Service for AmneziaVPN");
}

void SystemService::start()
{
    Logger::init(true);
    m_localServer  = new LocalServer();
}

void SystemService::stop()
{
    delete m_localServer;
}
