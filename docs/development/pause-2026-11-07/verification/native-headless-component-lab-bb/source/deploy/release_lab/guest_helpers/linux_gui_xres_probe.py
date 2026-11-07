"""Read-only X11/XRes query, invoked as lab with explicit DISPLAY/XAUTHORITY."""
import ctypes as C
import ctypes.util
import json

class Spec(C.Structure):
    _fields_=[('client',C.c_ulong),('mask',C.c_uint)]
class Value(C.Structure):
    _fields_=[('spec',Spec),('length',C.c_long),('value',C.c_void_p)]

def query():
    result={'diagnosticOnly':True,'identityGap':None}
    x=C.CDLL('libX11.so.6')
    def bind(lib,name,ret,args):
        f=getattr(lib,name);f.restype=ret;f.argtypes=args;return f
    ptr=C.c_void_p; ul=C.c_ulong; ip=C.POINTER(C.c_int)
    op=bind(x,'XOpenDisplay',ptr,[C.c_char_p]);close=bind(x,'XCloseDisplay',C.c_int,[ptr])
    rootfn=bind(x,'XDefaultRootWindow',ul,[ptr]);atom=bind(x,'XInternAtom',ul,[ptr,C.c_char_p,C.c_int])
    get=bind(x,'XGetWindowProperty',C.c_int,[ptr,ul,ul,C.c_long,C.c_long,C.c_int,ul,C.POINTER(ul),ip,C.POINTER(ul),C.POINTER(ul),C.POINTER(ptr)])
    free=bind(x,'XFree',C.c_int,[ptr]);sync=bind(x,'XSync',C.c_int,[ptr,C.c_int])
    handler_type=C.CFUNCTYPE(C.c_int,ptr,ptr)
    errors=[]
    result['x11Errors']=errors
    handler=handler_type(lambda *_:errors.append('X11ProtocolError') or 0)
    bind(x,'XSetErrorHandler',ptr,[handler_type])(handler)
    d=op(None)
    if not d:return dict(result,identityGap='display_unavailable')
    def prop(window,name):
        actual=ul();fmt=C.c_int();count=ul();after=ul();data=ptr()
        status=get(d,window,atom(d,name.encode(),1),0,1024,0,0,C.byref(actual),C.byref(fmt),C.byref(count),C.byref(after),C.byref(data))
        try:
            record={'status':status,'type':actual.value,'format':fmt.value,'items':count.value,'bytesAfter':after.value}
            if data and count.value<=1024:
                if fmt.value==32:record['values']=[C.cast(data,C.POINTER(ul))[i] for i in range(count.value)]
                elif fmt.value==8:record['text']=C.string_at(data,count.value).decode(errors='replace')
            return record
        finally:
            if data:free(data)
    try:
        try:
            extlib=C.CDLL('libXext.so.6');event=C.c_int();error=C.c_int()
            available=bind(extlib,'DPMSQueryExtension',C.c_int,[ptr,ip,ip])(d,C.byref(event),C.byref(error))
            dpms={'available':bool(available)};result['dpms']=dpms
            if available:
                level=C.c_ushort();enabled=C.c_ubyte();standby=C.c_ushort();suspend=C.c_ushort();off=C.c_ushort()
                dpms['capable']=bool(bind(extlib,'DPMSCapable',C.c_int,[ptr])(d))
                dpms['infoStatus']=bind(extlib,'DPMSInfo',C.c_int,[ptr,C.POINTER(C.c_ushort),C.POINTER(C.c_ubyte)])(d,C.byref(level),C.byref(enabled))
                dpms.update(level=level.value,enabled=bool(enabled.value))
                dpms['timeoutsStatus']=bind(extlib,'DPMSGetTimeouts',C.c_int,[ptr,C.POINTER(C.c_ushort),C.POINTER(C.c_ushort),C.POINTER(C.c_ushort)])(d,C.byref(standby),C.byref(suspend),C.byref(off))
                dpms['timeouts']=[standby.value,suspend.value,off.value]
        except (OSError,AttributeError) as error:result['dpms']={'gap':type(error).__name__}
        root=rootfn(d);record=prop(root,'_NET_SUPPORTING_WM_CHECK');result['rootWM']=record
        ids=record.get('values',[])
        if len(ids)!=1 or not ids[0]:return dict(result,identityGap='wm_child_unavailable')
        child=ids[0];result['childWM']=prop(child,'_NET_SUPPORTING_WM_CHECK');result['wmName']=prop(child,'_NET_WM_NAME');result['optionalEwmhPID']=prop(child,'_NET_WM_PID')
        if result['childWM'].get('values')!=[child]:return dict(result,identityGap='wm_self_reference_mismatch')
        if not result['wmName'].get('text'):result['identityGap']='wm_name_unavailable'
        name=C.util.find_library('XRes')
        if not name:return dict(result,identityGap='xres_library_unavailable')
        res=C.CDLL(name);event=C.c_int();error=C.c_int();major=C.c_int(1);minor=C.c_int(2)
        ext=bind(res,'XResQueryExtension',C.c_int,[ptr,ip,ip])(d,C.byref(event),C.byref(error))
        version=bind(res,'XResQueryVersion',C.c_int,[ptr,ip,ip])(d,C.byref(major),C.byref(minor)) if ext else 0
        result['xres']={'extension':bool(ext),'versionStatus':version,'version':[major.value,minor.value]}
        if not ext or not version or (major.value,minor.value)<(1,2):return dict(result,identityGap='xres_1_2_unavailable')
        values=C.POINTER(Value)();count=C.c_long();spec=Spec(child,2)
        status=bind(res,'XResQueryClientIds',C.c_int,[ptr,C.c_long,C.POINTER(Spec),C.POINTER(C.c_long),C.POINTER(C.POINTER(Value))])(d,1,C.byref(spec),C.byref(count),C.byref(values))
        rows=[]
        try:
            # Unlike QueryVersion's Bool, QueryClientIds returns X11 Success=0.
            if status==0 and 0<=count.value<=16:
                getpid=bind(res,'XResGetClientPid',C.c_int,[C.POINTER(Value)])
                for i in range(count.value):
                    value=values[i];rows.append({'client':value.spec.client,'mask':value.spec.mask,'length':value.length,'localPID':getpid(C.byref(value)),'rawValueHex':C.string_at(value.value,min(max(value.length,0),64)).hex() if value.value else '', 'valueTruncated':value.length>64})
        finally:
            if values:bind(res,'XResClientIdsDestroy',None,[C.c_long,C.POINTER(Value)])(count.value,values)
        result['xres'].update(status=status,count=count.value,reply=rows)
        pids={r['localPID'] for r in rows if r['mask']&2 and r['localPID']>0}
        if len(pids)==1:result['localPID']=next(iter(pids))
        else:result['identityGap']='xres_pid_missing_or_ambiguous'
        return result
    finally:
        sync(d,0);result['x11Errors']=errors;close(d)

if __name__=='__main__':
    try:print(json.dumps(query()))
    except Exception as error:print(json.dumps({'diagnosticOnly':True,'identityGap':'query_failed','errorType':type(error).__name__}))
