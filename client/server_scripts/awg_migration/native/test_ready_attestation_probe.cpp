#include "ready_attestation.h"
#include <iostream>
#include <iterator>
using namespace amnezia::awgMigration;
struct FakeRunner final:ProcessRunner {
 json_object *answers;std::size_t count=0;
 explicit FakeRunner(json_object *a):answers(a){}
 std::string run(const ProcessArgs &args) override {
  if(count>=json_object_array_length(answers))throw ConfigError("unexpected command");
  auto item=json_object_array_get_idx(answers,count++);auto expected=json_object_object_get(item,"args");
  if(json_object_array_length(expected)!=args.size())throw ConfigError("unexpected command");
  for(std::size_t n=0;n<args.size();++n)if(args[n]!=json_object_get_string(json_object_array_get_idx(expected,n)))throw ConfigError("unexpected command");
  auto hex=json_object_object_get(item,"output_hex");
  if(hex){
   std::string encoded=json_object_get_string(hex),bytes;
   if(encoded.size()%2)throw ConfigError("invalid fake byte output");
   for(std::size_t n=0;n<encoded.size();n+=2)bytes+=char(std::stoul(encoded.substr(n,2),nullptr,16));
   return bytes;
  }
  auto out=json_object_object_get(item,"output");return std::string(json_object_get_string(out),json_object_get_string_len(out));
 }
};
int main(){try{
 auto text=std::string(std::istreambuf_iterator<char>(std::cin),{});PlannerJson root(json_tokener_parse(text.c_str()));if(!root)return 2;
 auto get=[&](const char *key){return json_object_object_get(root.get(),key);};
 FakeRunner runner(get("answers"));
 if(json_object_get_boolean(get("existing")))validateExistingTarget(json_object_get_string(get("directory")),get("value"),get("ready"),runner);
 else validateReadyTarget(runner,get("ready"),parseConfig(json_object_get_string(get("source"))),parseConfig(json_object_get_string(get("target"))),json_object_get_boolean(get("automatic")));
 std::cout<<"OK\n";return 0;
 }catch(const std::exception &){std::cout<<"ERR\n";return 1;}}
