package com.technoboom.sniffer;

import java.util.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * Sniffer - contains
 */
public class Sniffer {
    /**
     * Runs sniffer
     *
     * @param args application arguments
     */
    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // contains NICs
        StringBuilder errbuf = new StringBuilder(); // contains error messages

        // find all connected devices on this system
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.ERROR || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }
        System.out.println("Network devices found:");

        int i = 0;
        for (PcapIf device : alldevs) {
            String description =
                    (device.getDescription() != null) ? device.getDescription()
                            : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        PcapIf device = alldevs.get(0); // We know we have atleast 1 device
        System.out
                .printf("\nChoosing '%s' on your behalf:\n",
                        (device.getDescription() != null) ? device.getDescription()
                                : device.getName());
    }
}