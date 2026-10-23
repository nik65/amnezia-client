package android.os
object Build {object VERSION {var SDK_INT=35};object VERSION_CODES{const val S=31}}
object Process {fun myUid()=1000}
object SystemClock {var now=0L;fun elapsedRealtime()=now}