package android.content
class Context(val cm:android.net.ConnectivityManager){fun <T>getSystemService(c:Class<T>):T?=c.cast(cm)}