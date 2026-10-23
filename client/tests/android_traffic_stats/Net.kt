package android.net
class Network(val networkHandle:Long)
class NetworkCapabilities(val ownerUid:Int,val vpn:Boolean=true){fun hasTransport(t:Int)=vpn;companion object{const val TRANSPORT_VPN=4}}
class LinkProperties(val interfaceName:String?)
class ConnectivityManager {val allNetworks get()=networks.toTypedArray();val networks=mutableListOf<Network>();val caps=mutableMapOf<Network,NetworkCapabilities>();val lp=mutableMapOf<Network,LinkProperties>();fun getNetworkCapabilities(n:Network)=caps[n];fun getLinkProperties(n:Network)=lp[n]}
object TrafficStats {const val UNSUPPORTED=-1;var rx=100L;var tx=200L;var readIface="";var hook:()->Unit={};var uidReads=0
fun getRxBytes(i:String):Long{readIface=i;return rx};fun getTxBytes(i:String):Long{hook();return tx}
fun getUidRxBytes(u:Int):Long{uidReads++;return rx};fun getUidTxBytes(u:Int):Long{uidReads++;return tx}}
