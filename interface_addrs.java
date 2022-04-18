/*
Example code for the addr of Run called ifaceAddrs.
This code is not actually used directly by this repo.

These two files were adapted and combined to form this file:

https://github.com/berty/berty/blob/7ff787f6dbff39f38c73d11393da593e615accdf/js/android/app/src/main/java/tech/berty/gobridge/NetDriver.java#L17-L72
https://github.com/tailscale/tailscale-android/blob/51fc2e7030191d08b434758dbd70a3a90338ef48/android/src/main/java/com/tailscale/ipn/App.java#L366-L398

*/

import java.net.NetworkInterface;
import java.lang.StringBuilder;
import java.util.Collections;
import java.net.SocketException;
import java.net.InterfaceAddress;

public class Example {

    String getInterfaceAddrs() {
        StringBuilder sb = new StringBuilder("");
        try {
            for (NetworkInterface nif : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                try {
                    for (InterfaceAddress ia : nif.getInterfaceAddresses()) {
                       String[] parts = ia.toString().split("/", 0);
                        if (parts.length > 1) {
                            sb.append(parts[1]);
                            sb.append("\n");
                        }
                    }
                } catch (Exception e) {
                    // TODO should log the exception not silently suppress it.
                    continue;
                }
            }
        } catch (SocketException e) {
            // TODO: log
        }
        return sb.toString();
    }
    
}
