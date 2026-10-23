// Test-only read interposer. It only modifies an explicitly named owned fixture.
#include <dlfcn.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <sys/stat.h>
#include <fcntl.h>
extern "C" ssize_t read(int fd,void *buffer,size_t count) {
 using Read=ssize_t(*)(int,void*,size_t);
 static auto original=reinterpret_cast<Read>(dlsym(RTLD_NEXT,"read"));
 if(!original)_exit(91);
 static bool swapped=false;const char *dir=std::getenv("OWNED_ATTESTATION_SWAP_DIR");
 if(dir&&!swapped) {
  char proc[128],path[4096],expected[4096],moved[4096];
  std::snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
  auto n=readlink(proc,path,sizeof(path)-1);
  if(n>=0) {
   path[n]=0;std::snprintf(expected,sizeof(expected),"%s/awg0.conf",dir);
   if(!std::strcmp(path,expected)) {
    swapped=true;std::snprintf(moved,sizeof(moved),"%s.moved",dir);
    if(rename(dir,moved)||mkdir(dir,0700))_exit(92);
    int replacement=open(expected,O_WRONLY|O_CREAT|O_EXCL,0600);if(replacement<0)_exit(93);
    const char text[]="replacement-invalid-config\n";
    if(write(replacement,text,sizeof(text)-1)!=static_cast<ssize_t>(sizeof(text)-1))_exit(94);
    close(replacement);
   }
  }
 }
 return original(fd,buffer,count);
}
