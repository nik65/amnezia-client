#include "rollbackCliResponse.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <cassert>
#include <iostream>
using namespace amnezia::headless;
int main(int argc,char **argv){QCoreApplication app(argc,argv);int checks=0;auto check=[&](bool b){++checks;assert(b);};
RollbackCoordinatorResult scheduled{true,"rollback_restart_pending",{},{{"authority","retained14Coordinator"},{"phase","rollback_requested"},{"operationId","owned-operation"}}};
const auto frame=acceptedPendingRollbackResponse("owned-request","peer closed before response",scheduled);check(!frame.isEmpty()&&frame.size()<=MaximumFrameSize);const auto doc=QJsonDocument::fromJson(frame).object();check(doc.value("ok").toBool());check(doc.value("id")=="owned-request");const auto result=doc.value("result").toObject();check(result.value("pending").toBool());check(result.value("state")=="rollback_coordinator_accepted_pending");check(result.value("authority")=="retained14CoordinatorRequest");check(result.value("transportFailure")=="peer closed before response");check(result.value("coordinator").toObject()==scheduled.evidence);
for(int kind=0;kind<5;++kind){auto bad=scheduled;if(kind==0)bad.ok=false;if(kind==1)bad.code="held";if(kind==2)bad.evidence.insert("authority","daemon13");if(kind==3)bad.evidence.insert("phase","held");if(kind==4)bad.evidence={};check(acceptedPendingRollbackResponse("id","EOF",bad).isEmpty());}
auto oversized=scheduled;oversized.evidence.insert("unexpectedHuge",QString(80*1024,'x'));auto bounded=acceptedPendingRollbackResponse("id","EOF",oversized);check(bounded.size()<=MaximumFrameSize);check(!QJsonDocument::fromJson(bounded).object().value("ok").toBool());
QJsonObject admission{{"authority","retained14Coordinator"},{"phase","profiles_paused"}};
QJsonObject coordinator{{"schema",1},{"workerStartRequested",true},{"admission",admission}};
auto daemonFrame=[&](const QJsonObject &c){return encodeResponse("owned-request",{{"rollbackCoordinator",c}});};
check(daemonScheduledRollback(daemonFrame(coordinator)));
for(int kind=0;kind<8;++kind){auto bad=coordinator;if(kind==0)bad.insert("schema",true);if(kind==1)bad.insert("schema","1");if(kind==2)bad.insert("schema",2);if(kind==3)bad.insert("workerStartRequested",1);if(kind==4)bad.insert("workerStartRequested",false);if(kind==5)bad.remove("workerStartRequested");if(kind==6)bad.insert("admission",QJsonObject{{"authority","daemon13"},{"phase","profiles_paused"}});if(kind==7)bad.insert("admission",QJsonObject{{"authority","retained14Coordinator"},{"phase","held"}});check(!daemonScheduledRollback(daemonFrame(bad)));}
check(!daemonScheduledRollback(encodeError("owned-request","refused","actual daemon refusal")));check(!daemonScheduledRollback("malformed"));
// Integration source contract only: no live prepare/systemd is invoked here.
QFile cli(ACTUAL_CLI_SOURCE);check(cli.open(QIODevice::ReadOnly));const auto source=cli.readAll();auto absence=source.indexOf("if (responseFrame.isEmpty())");auto fallback=source.indexOf("acceptedPendingRollbackResponse",absence);auto explicitSuccess=source.indexOf("if (coordinatedRollback && QJsonDocument::fromJson(responseFrame).object()",absence);check(absence>=0&&fallback>absence&&explicitSuccess>fallback);check(source.mid(explicitSuccess).contains(".value(QStringLiteral(\"ok\")).toBool(false)"));check(source.mid(explicitSuccess).contains("return printResponse(responseFrame"));check(source.mid(explicitSuccess).contains("&& !amnezia::headless::daemonScheduledRollback(responseFrame)"));
std::cout<<"actual pending response header checks="<<checks<<"; CLI absence/refusal ordering source contract only\n";
}
