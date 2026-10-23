#include "transaction_journal.h"
#include <iostream>
#include <iterator>
#include <map>
using namespace amnezia::awgMigration;
// Test-only parity driver. It has no live process/Docker implementation.
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    try {
        const std::string input{std::istreambuf_iterator<char>(std::cin),{}};
        json_object* scenario=json_tokener_parse(input.c_str());
        if(!scenario)return 2;
        std::shared_ptr<json_object> cleanup(scenario,json_object_put);
        auto* commands=json_object_new_array();
        std::shared_ptr<json_object> commandsCleanup(commands,json_object_put);
        auto* inspections=json_object_object_get(scenario,"inspections");
        JournalRunner runner=[&](const std::vector<std::string>& args){
            auto* command=json_object_new_array();
            for(const auto& arg:args)json_object_array_add(command,json_object_new_string(arg.c_str()));
            json_object_array_add(commands,command);
            if(args.size()==3&&args[1]=="inspect"){
                json_object* item=nullptr;
                if(!json_object_object_get_ex(inspections,args[2].c_str(),&item))return CommandResult{1,"","No such object"};
                return CommandResult{0,"["+std::string(json_object_to_json_string_ext(item,JSON_C_TO_STRING_PLAIN))+"]",""};
            }
            return CommandResult{};
        };
        const auto initial=std::string(json_object_to_json_string_ext(json_object_object_get(scenario,"initial"),JSON_C_TO_STRING_PLAIN));
        TransactionJournal journal(argv[1],runner,initial);
        auto* operations=json_object_object_get(scenario,"operations");
        bool rejected=false;
        try {
            for(std::size_t i=0;i<json_object_array_length(operations);++i){
                auto* op=json_object_array_get_idx(operations,i);
                std::string action=json_object_get_string(json_object_object_get(op,"op"));
                if(action=="plan")journal.plan(json_object_get_string(json_object_object_get(op,"name")),json_object_get_string(json_object_object_get(op,"image")));
                else if(action=="record")journal.record(json_object_get_string(json_object_object_get(op,"name")));
                else if(action=="cleanup")journal.cleanup();
                else if(action=="save")journal.save(json_object_get_string(json_object_object_get(op,"phase")));
                else if(action=="recoverReady")journal.recoverReady([](const std::string&){});
                else return 2;
            }
        }catch(const JournalError&){rejected=true;}
        auto* output=json_object_new_object();
        std::shared_ptr<json_object> outputCleanup(output,json_object_put);
        json_object_object_add(output,"snapshot",json_tokener_parse(journal.snapshot().c_str()));
        json_object_object_add(output,"commands",json_object_get(commands));
        json_object_object_add(output,"rejected",json_object_new_boolean(rejected));
        std::cout<<json_object_to_json_string_ext(output,JSON_C_TO_STRING_PLAIN)<<'\n';
        return 0;
    }catch(const std::exception&){return 1;}
}
