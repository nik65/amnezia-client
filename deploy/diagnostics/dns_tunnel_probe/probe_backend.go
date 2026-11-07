// Isolated, bounded diagnostic endpoint. No arbitrary/open proxy and no app integration.
package main

import (
 "crypto/sha256"
 "crypto/subtle"
 "encoding/hex"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "os"
 "strconv"
 "strings"
 "sync"
 "time"
)

func main() {
 tokenBytes, err := os.ReadFile(os.Args[1]); if err != nil {log.Fatal("credential unreadable")}
 expected := []byte("Bearer " + strings.TrimSpace(string(tokenBytes)))
 slots:=make(chan struct{},4)
 handler:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")),expected)!=1 {http.Error(w,"unauthorized",401);return}
  select {case slots<-struct{}{}: defer func(){<-slots}();default: http.Error(w,"busy",503);return}
  if r.Method=="CONNECT" {
   if r.Host!="example.com:443" && r.Host!="www.wikipedia.org:443" {http.Error(w,"target not allowed",403);return}
   dest,err:=net.DialTimeout("tcp",r.Host,20*time.Second);if err!=nil {http.Error(w,"upstream unavailable",502);return};defer dest.Close()
   conn,rw,err:=w.(http.Hijacker).Hijack();if err!=nil{return};defer conn.Close()
   deadline:=time.Now().Add(180*time.Second);conn.SetDeadline(deadline);dest.SetDeadline(deadline)
   rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n");if rw.Flush()!=nil{return}
   var wg sync.WaitGroup;wg.Add(1)
   go func(){defer wg.Done();io.Copy(dest,io.LimitReader(rw,2<<20));if c,ok:=dest.(*net.TCPConn);ok{c.CloseWrite()}}()
   io.Copy(conn,io.LimitReader(dest,2<<20));conn.Close();dest.Close();wg.Wait()
   log.Print("authenticated CONNECT completed target=",r.Host);return
  }
  if r.Method!="POST" || r.URL.Path!="/probe" {http.NotFound(w,r);return}
  if r.ContentLength<1 || r.ContentLength>1<<20 {http.Error(w,"length out of range",413);return}
  digest:=sha256.New();n,err:=io.Copy(digest,http.MaxBytesReader(w,r.Body,1<<20));if err!=nil || n!=r.ContentLength{http.Error(w,"incomplete upload",400);return}
  data:=make([]byte,n);for i:=range data{data[i]=byte((i*37+i/256)%256)}
  down:=sha256.Sum256(data)
  w.Header().Set("X-Upload-SHA256",hex.EncodeToString(digest.Sum(nil)))
  w.Header().Set("X-Download-SHA256",hex.EncodeToString(down[:]))
  w.Header().Set("Content-Type","application/octet-stream")
  w.Header().Set("Content-Length",strconv.FormatInt(n,10))
  w.WriteHeader(200);sent,err:=w.Write(data)
  log.Printf("authenticated probe upload=%d download=%d complete=%t",n,sent,err==nil&&sent==len(data))
 })
 server:=&http.Server{Addr:"127.0.0.1:18081",Handler:handler,ReadHeaderTimeout:30*time.Second,ReadTimeout:300*time.Second,WriteTimeout:300*time.Second,IdleTimeout:30*time.Second,MaxHeaderBytes:8192}
 fmt.Println("bounded diagnostic backend 127.0.0.1:18081")
 log.Fatal(server.ListenAndServe())
}
