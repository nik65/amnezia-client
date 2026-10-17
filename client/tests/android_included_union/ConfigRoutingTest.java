import java.net.InetAddress;
import android.os.Build;
import org.amnezia.vpn.protocol.BadConfigException;
import org.amnezia.vpn.protocol.ProtocolConfig;
import org.amnezia.vpn.protocol.ProtocolErrorReason;
import org.amnezia.vpn.protocol.wireguard.WireguardConfig;
import org.amnezia.vpn.util.net.InetEndpoint;
import org.amnezia.vpn.util.net.InetNetwork;

/** Runs actual compiled production config classes on a JVM; no Android guest. */
public final class ConfigRoutingTest {
    private static void populate(WireguardConfig.Builder builder, boolean sites, boolean apps, boolean ipv6)
        throws Exception {
        builder.setPrivateKeyHex("00".repeat(32));
        builder.setPublicKeyHex("11".repeat(32));
        builder.setEndpoint(new InetEndpoint(InetAddress.getByName("192.0.2.1"), 51820));
        builder.addAddress(new InetNetwork("10.66.66.2", 32));
        builder.addRoute(new InetNetwork("0.0.0.0", 0));
        builder.addRoute(new InetNetwork("::", 0));
        builder.setAllowIpv6Routes(ipv6);
        if (sites) builder.includeAddress(new InetNetwork("198.51.100.2", 32));
        if (apps) builder.includeApplication("example.selected");
    }

    private static WireguardConfig config(boolean sites, boolean apps, boolean ipv6) throws Exception {
        WireguardConfig.Builder builder = new ModernAndroidBuilder();
        populate(builder, sites, apps, ipv6);
        return builder.build();
    }

    private static final class ModernAndroidBuilder extends WireguardConfig.Builder {
        @Override
        protected int androidApiLevel() {
            return Build.VERSION_CODES.Q;
        }
    }

    private static final class LegacyAndroidBuilder extends WireguardConfig.Builder {
        @Override
        protected int androidApiLevel() {
            return Build.VERSION_CODES.P;
        }
    }

    private static void assertLegacyCombinedRejected() throws Exception {
        for (boolean extension : new boolean[] { false, true }) {
            LegacyAndroidBuilder builder = new LegacyAndroidBuilder();
            populate(builder, true, true, true);
            builder.setUseProtocolExtension(extension);
            try {
                builder.build();
                throw new AssertionError("combined lists must fail before VPN establishment on Android < 10");
            } catch (Exception expected) {
                if (!(expected instanceof BadConfigException)
                    || !expected.getMessage().contains("Android 10"))
                    throw new AssertionError("legacy combined rejection lost its actionable reason", expected);
                if (((BadConfigException) expected).getReasonCode()
                    != ProtocolErrorReason.COMBINED_ROUTING_REQUIRES_ANDROID_10)
                    throw new AssertionError("legacy combined rejection lost its typed reason code", expected);
                if (((BadConfigException) expected).getReasonCode() != 105)
                    throw new AssertionError("cross-language Android reason code drifted");
            }
        }

        for (boolean sitesOnly : new boolean[] { true, false }) {
            LegacyAndroidBuilder supported = new LegacyAndroidBuilder();
            populate(supported, sitesOnly, !sitesOnly, true);
            if (supported.build().getUseIncludedUnion())
                throw new AssertionError("one included list on API28 must retain its ordinary routing mode");
        }

        try {
            new ModernAndroidBuilder().build();
            throw new AssertionError("an invalid ordinary config must still fail");
        } catch (Exception expected) {
            if (!(expected instanceof BadConfigException)
                || ((BadConfigException) expected).getReasonCode() != 0)
                throw new AssertionError("generic config failures must not masquerade as API28 union failures");
        }
    }

    private static boolean default4(ProtocolConfig config) {
        return config.getRoutes().stream().anyMatch(route -> route.getInclude()
            && route.getInetNetwork().equals(new InetNetwork("0.0.0.0", 0)));
    }

    public static void main(String[] args) throws Exception {
        assertLegacyCombinedRejected();
        WireguardConfig both = config(true, true, true);
        if (!both.getUseIncludedUnion() || !default4(both))
            throw new AssertionError("combined lists must admit all destinations for native classification");
        if (!both.toWgUserspaceString().contains("allowed_ip=0.0.0.0/0\n"))
            throw new AssertionError("selected apps need default native peer AllowedIPs");
        if (both.getIncludedApplications().size() != 1 || both.getIncludedAddresses().size() != 1)
            throw new AssertionError("native union policy lost one selection list");
        WireguardConfig sites = config(true, false, true);
        if (sites.getUseIncludedUnion() || default4(sites))
            throw new AssertionError("sites-only mode must retain route restriction");
        WireguardConfig apps = config(false, true, true);
        if (apps.getUseIncludedUnion() || !default4(apps))
            throw new AssertionError("apps-only mode must retain the platform UID restriction");
        WireguardConfig ipv4 = config(true, true, false);
        if (ipv4.getRoutes().stream().anyMatch(route -> route.getInetNetwork().isIpv6()))
            throw new AssertionError("IPv4-only server gained IPv6 routes");
        System.out.println("production Android config: combined union, single filters, peer AllowedIPs and IPv4 gate PASS");
    }
}
