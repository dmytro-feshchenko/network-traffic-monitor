package com.technoboom.sniffer;

//import java.util.*;
//
//import org.jnetpcap.Pcap;
//import org.jnetpcap.PcapIf;
//import org.jnetpcap.packet.PcapPacket;
//import org.jnetpcap.packet.PcapPacketHandler;

import net.sourceforge.jpcap.capture.*;
import net.sourceforge.jpcap.net.*;

/**
 * Sniffer - contains
 */
public class Sniffer {
        private static final int INFINITE = -1;
        private static final int PACKET_COUNT = 10;

        // BPF filter for capturing any packet
        private static final String FILTER = "";

        private PacketCapture m_pcap;
        private String m_device;

        public Sniffer() throws Exception {
            // Step 1:  Instantiate Capturing Engine
            m_pcap = new PacketCapture();

            // Step 2:  Check for devices
            m_device = m_pcap.findDevice();

            // Step 3:  Open Device for Capturing (requires root)
            m_pcap.open(m_device, true);

            // Step 4:  Add a BPF Filter (see tcpdump documentation)
            m_pcap.setFilter(FILTER, true);

            // Step 5:  Register a Listener for Raw Packets
            m_pcap.addRawPacketListener(new RawPacketHandler());

            // Step 6:  Capture Data (max. PACKET_COUNT packets)
            m_pcap.capture(PACKET_COUNT);
        }
    /**
     * Runs sniffer
     *
     * @param args application arguments
     */
    public static void main(String[] args) {
//        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // contains NICs
//        StringBuilder errbuf = new StringBuilder(); // contains error messages
//
//        // find all connected devices on this system
//        int r = Pcap.findAllDevs(alldevs, errbuf);
//        if (r == Pcap.ERROR || alldevs.isEmpty()) {
//            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
//            return;
//        }
//        System.out.println("Network devices found:");
//
//        int i = 0;
//        for (PcapIf device : alldevs) {
//            String description =
//                    (device.getDescription() != null) ? device.getDescription()
//                            : "No description available";
//            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
//        }
//
//        PcapIf device = alldevs.get(0); // We know we have atleast 1 device
//        System.out
//                .printf("\nChoosing '%s' on your behalf:\n",
//                        (device.getDescription() != null) ? device.getDescription()
//                                : device.getName());
        try {
            System.out.println(System.getProperty("java.library.path"));
            Sniffer example = new Sniffer();
        } catch(Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}

class RawPacketHandler implements RawPacketListener
{
    private static int m_counter = 0;

    public void rawPacketArrived(RawPacket data) {
        m_counter++;
        System.out.println("Received packet (" + m_counter + ")");
    }
}