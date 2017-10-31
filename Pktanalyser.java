/**
 * filename: Pktanalyser.java
 *
 * Programe to print the TCP/UDP/ICMP packets.
 *
 * Version $1.1
 * @author: Ketan Joshi(ksj4205)
 *
 */
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class Pktanalyser {
    /**
     * Main function
     * @param args Commandline Argument
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        Path p = Paths.get(args[0]);

        String hexStr = GivemeHexStrind(p);

        // call to print Ethernet Header
        PrintEtherHeader(hexStr);

        int HeaderLength =Integer.parseInt(hexStr.substring(29,30))*4;

        // call to print the IP header
        int protocol =PrintIPHeader(hexStr);

        // call to print the protocol header.
        PrintProtocolHeader(hexStr,protocol,HeaderLength+14);

    }

    /**
     * Function to print the protocol header
     * @param hex :Strig of data in hexadecimal format
     * @param protocol : protocol number
     * @param start : the starting index of the protocol header
     */
    private static void PrintProtocolHeader(String hex,int protocol, int start) {
        start=start*2;
        if(protocol ==1)
            PrintICMPHeader(hex,start);
        if(protocol ==6)
            PrintTCPHeader(hex,start);
        if(protocol ==17)
            PrintUDPHeader(hex,start);

    }

    /**
     * Funcion to print the UDP header
     * @param hex  :Strig of data in hexadecimal format
     * @param start : the starting index of the protocol header
     */
    public static void PrintUDPHeader(String hex,int start)
    {
        hex=hex.substring(start);
        typeUDP(0);
        System.out.println("----- UDP Header -----");
        typeUDP(1);
        typeUDP(0);
        System.out.println("Source port = "+hex2deci(hex.substring(0,4)));
        typeUDP(0);
        System.out.println("Destination port ="+hex2deci(hex.substring(4,8)));
        typeUDP(0);
        System.out.println("Length = "+hex2deci(hex.substring(8,12)));
        typeUDP(0);
        System.out.println("Checksum = "+hex.substring(12,16));
        typeUDP(0);
        System.out.println("Data: ");
        PrintData(hex,16,17);


    }

    /**
     * function to type "UDP :" as per the output specification
     * @param n : parameter 0 or 1; 1 implies to include nextLine character
     *
     */
    public static void typeUDP(int n)
    {
        System.out.print("UDP:  ");
        if(n==1)
            System.out.println();
    }

    /**
     * Function to tupe TCP header
     * @param hex :Strig of data in hexadecimal format
     * @param start : the starting index of the protocol header
     */
    public static void PrintTCPHeader(String hex,int start)
    {
        hex=hex.substring(start);
        typeTCP(0);
        System.out.println("----- TCP Header -----");
        typeTCP(1);
        typeTCP(0);
        System.out.println("Source port = "+hex2deci(hex.substring(0,4)));
        typeTCP(0);
        System.out.println("Destination port ="+hex2deci(hex.substring(4,8)));
        typeTCP(0);
        System.out.println("Sequence number = "+AckmSeqNumber(hex.substring(8,16)));
        typeTCP(0);
        System.out.println("Acknowledgement number = "+AckmSeqNumber(hex.substring(16,24)));
        typeTCP(0);
        int dataoffset =Integer.parseInt(hex.substring(24,25))*4;
        System.out.println("Data offset = "+dataoffset+" bytes");
        typeTCP(0);
        String controlbits = hex2bin(hex.substring(26,28));

        System.out.println("Flags = 0x"+hex.substring(26,28));

        String urgent_ptr,ack,push,syn,reset,fin;
        if(controlbits.charAt(2)=='1')
            urgent_ptr ="urgent pointer";
        else
            urgent_ptr=" No urgent pointer";
        if(controlbits.charAt(3)=='1')
            ack ="Acknowledgment";
        else
            ack="No Acknowledgment";
        if(controlbits.charAt(4)=='1')
            push ="push";
        else
            push ="no push";
        if (controlbits.charAt(5)=='1')
            reset ="reset";
        else
            reset ="No reset";
        if (controlbits.charAt(6)=='1')
            syn="syn";
        else
            syn="No syn";
        if (controlbits.charAt(7)=='1')
            fin="fin";
        else
            fin="No fin";
        typeTCP(0);
        System.out.println("      .."+controlbits.charAt(2)+". .... = "+urgent_ptr);
        typeTCP(0);
        System.out.println("      ..."+controlbits.charAt(3)+" .... = "+ack);
        typeTCP(0);
        System.out.println("      .... "+controlbits.charAt(4)+"... = "+push);
        typeTCP(0);
        System.out.println("      .... ."+controlbits.charAt(5)+".. = "+reset);
        typeTCP(0);
        System.out.println("      .... .."+controlbits.charAt(6)+". = "+syn);
        typeTCP(0);
        System.out.println("      .... ..."+controlbits.charAt(7)+" = "+fin);
        typeTCP(0);
        System.out.println("Window = "+hex2deci(hex.substring(28,32)));
        typeTCP(0);
        System.out.println("Checksum = 0x"+hex.substring(32,36));
        typeTCP(0);
        System.out.println("Urgent pointer = "+hex2deci(hex.substring(36,40)));
        typeTCP(0);
        if(dataoffset>20)
            System.out.println("Options exist("+(dataoffset-20)+") bytes");
        else
            System.out.println("No Options");
        PrintData(hex,dataoffset*2,6);





    }

    /**
     * Function to print the data in the protocol header.
     * @param hex2 :The data String in hexadecimal format
     * @param start : : the starting index of the Data
     * @param protocol : the protocol Number
     */
    private static void PrintData(String hex2, int start, int protocol) {

        String hex = hex2.substring(start);
        int limit;
        // to print the first 64 bytes of data
        if (hex.length() >= 128)
            limit = 128;
        else
            limit = hex.length();
        typeProtocol(protocol);

        if(hex.length()==0)
        {
            System.out.println("No Data");

            typeProtocol(protocol);
            return;
        }

        System.out.println("Data: (first "+limit/2+ "bytes)");
        typeProtocol(protocol);

        String str ="";
        //For loop to print the data
        for (int i = 0; i < limit; i++) {

            String chr ;

            if (i % 4 == 0 && i != 0 && i%32!=0)
                System.out.print(" ");

            System.out.print(hex.charAt(i));
            if(i%2==1)
            {
                int deci = hex2deci(hex.substring(i-1,i+1));
                if(deci<=126 && deci >=33)
                {
                    chr = Character.toString((char)deci);
                    str+=chr;
                }
                else
                    str+=".";
            }
        //Logic to print the data at correct spacing
        if ((i+1)%32==0||i == limit-1) {
                if(i== limit-1&&(i+1)%32!=0)
                {
                    int j = 32-(limit%32);
                    j=j+(j/4);
               for(int k =0;k<j;k++)
                   System.out.print(" ");
                }

            System.out.print("    " + (char) 34 + str + (char) 34);
            System.out.println();
            str="";
            typeProtocol(protocol);
        }

    }

    }

    /**
     * Function to print "protocol_name: "
     * @param protocol : contains the protocol number
     */
    public static void typeProtocol(int protocol)
    {
        if(protocol ==1)
            typeICMP(0);
        if(protocol ==6)
            typeTCP(0);
        if(protocol ==17)
            typeUDP(0);
    }

    /**
     * Function "TCP: "
     * @param n : could be 0 or 1
     *          1 implies to print the nextLine character
     */
    public static void typeTCP(int n)
    {
        System.out.print("TCP:  ");
        if(n==1)
            System.out.println();

    }

    /**
     * Function to print the ICMP header
     * @param hex: The string data in hexa decimal format
     * @param start : the start index of protocol in the string
     */
    public static void PrintICMPHeader(String hex,int start)
    {
        hex=hex.substring(start);
        typeICMP(0);
        System.out.println("----- ICMP Header -----");
        typeICMP(1);
        typeICMP(0);
        System.out.println("Type = "+hex2deci(hex.substring(0,2)));
        typeICMP(0);
        System.out.println("Code = "+hex2deci(hex.substring(2,4)));
        typeICMP(0);
        System.out.println("Checksum = "+hex.substring(4,8));
        typeICMP(1);

    }

    /**
     * Function to print "ICMP:  "
     * @param n : it could be 0 or 1
     *          1 means to include the nextLine character
     */
    public static void typeICMP(int n)
    {
        System.out.print("ICMP:  ");
        if(n==1)
            System.out.println();
    }

    /**
     * Function to print the Ethernet Header
     * @param hexStr : the data String in hexadecimal format
     */
    public static void PrintEtherHeader(String hexStr)
    {
        typeEther(0);
        System.out.println("----- Ether Header ----- ");
        typeEther(1);
        typeEther(0);
        System.out.println("Packet size = "+hexStr.length()/2+" bytes");
        typeEther(0);
        System.out.println("Destination = "+destmacaddr(hexStr)+",");
        typeEther(0);
        System.out.println("Source      = "+srcmacaddr(hexStr)+",");
        typeEther(0);
        System.out.println("Ethertype   = "+hexStr.substring(24,28)+"(IP)");
        typeEther(1);
    }

    /**
     * Function to print the IP header
     * @param hexStr : the string of data in Hexadecimal format
     * @return : returns the protocol number found in the IP header
     */
    public static int PrintIPHeader(String hexStr)
    {
        int start_index =28;
        int end_index=Integer.parseInt(hexStr.substring(29,30))*4;
        typeIP(0);
        System.out.println("----- IP Header -----");
        typeIP(1);
        typeIP(0);
        System.out.println("Version = " +hexStr.substring(28,29));
        int HeaderLength =Integer.parseInt(hexStr.substring(29,30))*4;
        typeIP(0);
        System.out.println("Header length = "+HeaderLength+" bytes");
        typeIP(0);
        System.out.println("Type of service = 0x"+hexStr.substring(30,32));
        String TypeofService = hex2bin(hexStr.substring(30,32));

        typeIP(0);
        System.out.println("      xxx. .... = "+givemeDecimalfromBinary(TypeofService.substring(0,3))+"(precedence)");
        String delay,throughput,reliability;
        if(TypeofService.charAt(3)=='0')
            delay="normal";
        else
            delay="low";
        if(TypeofService.charAt(4)=='0')
            throughput="normal";
        else
            throughput="high";
        if(TypeofService.charAt(5)=='0')
            reliability="normal";
        else
            reliability="high";
        typeIP(0);
        System.out.println("      ..."+TypeofService.charAt(3)+" .... = "+delay+" delay");
        typeIP(0);
        System.out.println("      .... "+TypeofService.charAt(4)+"... = "+throughput+" throughput");
        typeIP(0);
        System.out.println("      .... ."+TypeofService.charAt(5)+".. = "+reliability+" reliability");
        typeIP(0);
        System.out.println("Total length = "+hex2deci(hexStr.substring(32,36))+" bytes");
        typeIP(0);
        System.out.println("Identification = "+hex2deci(hexStr.substring(36,40)));
        typeIP(0);
        System.out.println("Flags = 0x"+hexStr.substring(40,41));
        String flags = hex2bin(hexStr.substring(40,41));
        String m,f;
        if(flags.charAt(1)=='0')
            m ="Fragment if necessary";
        else
            m="Do not fragment";
        if(flags.charAt(2)=='0')
            f="last fragment";
        else
            f="More fragments follow this fragment";
        typeIP(0);
        System.out.println("      ."+flags.charAt(1)+".. .... = "+m);
        typeIP(0);
        System.out.println("      .."+flags.charAt(2)+". .... = "+f);
        typeIP(0);
        System.out.println("Fragment offset = "+givemeDecimalfromBinary(hex2bin(hexStr.substring(40,44)).substring(3))
        +" bytes");
        typeIP(0);
        System.out.println("Time to live = "+hex2deci(hexStr.substring(44,46))+" seconds/hops ");
        String protocol;
        int protocolNum =hex2deci(hexStr.substring(46,48));
        if((protocolNum==17))
            protocol="UDP";
        else if(protocolNum==1)
            protocol ="ICMP";
        else if (protocolNum==6)
            protocol="TCP";
        else
            protocol="Unknown";
        typeIP(0);
        System.out.println("Protocol ="+hex2deci(hexStr.substring(46,48))+" ("+protocol+")");
        typeIP(0);
        System.out.println("Header checksum = "+hexStr.substring(48,52));
        String scrIP = getIPaddr(hexStr.substring(52,60));
        String destIP = getIPaddr(hexStr.substring(60,68));
        try {
            InetAddress addr = InetAddress.getByName(scrIP);
            String host = addr.getHostName();
            typeIP(0);
            if(scrIP.equals(host))
                host = "(hostname unknown)";
            System.out.println("Source address = "+scrIP+", "+host);
            addr = InetAddress.getByName(destIP);
            host = addr.getHostName();
            if(destIP.equals(host))
                host = "(hostname unknown)";
            typeIP(0);
            System.out.println("Destination address = "+destIP+", "+host);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        String options;
        if(HeaderLength+14>34)
            options ="Option Field  Exist";
        else
            options = "No options";
        typeIP(0);
        System.out.println(options);
        typeIP(1);

return protocolNum;
    }

    /**
     * Function to return the acknowledgment or sequence number
     * @param hex : the string of data in hexadecimal format
     * @return returns the acknoledgment number or sequence number
     */
    public static BigInteger AckmSeqNumber(String hex) {

        BigInteger[] deci_library = {BigInteger.TEN, new BigInteger("11"), new BigInteger("12"), new BigInteger("13"),
                new BigInteger("14"), new BigInteger("15")};
        BigInteger decimal = new BigInteger("0");
        BigInteger j = new BigInteger("0");
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(hex.length() - 1 - i);

            if (Character.isLetter(c)) {
                if (Character.isUpperCase(c))
                    j = deci_library[c - 'A'];
                else
                    j = deci_library[c - 'a'];
                decimal = decimal.add((new BigInteger("16").pow(i)).multiply(j));
            } else {
                j = new BigInteger(hex.substring(hex.length() - 1 - i, hex.length() - i));
                decimal = decimal.add((new BigInteger("16").pow(i)).multiply(j));
            }

        }
        return decimal;
    }

    /**
     * Function to return the IP address from the hexadecimal string
      * @param hex : contains the IP address in hexadecimal format
     * @return : returns the IP address in string format
     */
    public  static String getIPaddr(String hex)
    {
        String IP ="";
        for(int i=0;i<hex.length();i+=2)
        {
            int temp = hex2deci(hex.substring(i,i+2));
            IP+=temp;
            if(i!=hex.length()-2)
                IP+=".";
        }
        return IP;
    }


    /**
     * Converts the hexadecimal number to decimal format
     * @param hex : contains the hexadecimal number
     * @return : returns the decimal equivalent of hexadecimal
     */
    public static int hex2deci(String hex)
    {
        int[] deci_library={10,11,12,13,14,15};
        int decimal =0;
        int j =0;
        for(int i=0;i<hex.length();i++)
        {
            char c=hex.charAt(hex.length()-1-i);

            if(Character.isLetter(c))
            {
                if(Character.isUpperCase(c))
                    j=deci_library[c-'A'];
                else
                    j=deci_library[c-'a'];
                decimal += (int)Math.pow(16,i)*j;
            }
            else
            { j = Integer.parseInt(hex.substring(hex.length()-1-i,hex.length()-i));
            decimal += (int)Math.pow(16,i)*j;
        }

    }
        return decimal;
    }

    /**
     * function to calculate binary equivalent of the hexadecimal string
     * @param hex : hexadecimal number
     * @return : returns the binary equivalent of hexadecimal string
     */
    public static String hex2bin(String hex)
    {
        String[] bin_library ={"0000","0001","0010","0011","0100","0101","0110","0111","1000","1001","1010","1011",
                "1100","1101","1110","1111"};
        String bin="";
        for(int i=0;i<hex.length();i++)
        {
            char c=hex.charAt(i);

            if(Character.isLetter(c))
            {
                if(Character.isUpperCase(c))
                    bin+=bin_library[c-'A'+10];
                else
                    bin+=bin_library[c-'a'+10];
            }
            else// if(c>='0' || c<='9')
            {
                int j = Integer.parseInt(hex.substring(i,i+1));
                bin = bin+ bin_library[j];
            }
        }
        return bin;
    }

    /**
     * Types "IP: "
     * @param n : could be either 0 or 1
     *          1 means to include the nextLine character
     */
    public static void typeIP(int n)
    {
        System.out.print("IP:   ");
        if(n==1)
            System.out.println();

    }

    /**
     * calculate the destination mac address
     * @param s : hexadecimal string of the address
     * @return : returns the mac adresss
     */
    public static String destmacaddr(String s)
    {
        String st="";
        for(int i =0;i<6;i++)
        {
            st=st+s.substring(2*i,2*i+2);
            if (i!=5)
                st=st+":";
        }
        return st;
    }

    /**
     * calculate the source mac address
     * @param s : hexadecimal string of the address
     * @return : returns the mac adresss
     */
    public static String srcmacaddr(String s)
    {
        String st="";
        for(int j =12;j<24;j+=2)
        {

            st=st+s.substring(j,j+2);
            if (j!=23)
                st=st+":";
        }
        return st;
    }

    /**
     * Types "Ether: " according to the output specification
     * @param n : could be either 0 or 1
     *          1 means to include the nextLine character
     */
    public static void typeEther(int n)
    {
        System.out.print("ETHER:  ");
        if(n==1)
            System.out.println();
    }

    /**
     * Function to convert the stream of bytes in hexadecimal format
     * @param p : is the path of the binary file in the system
     * @return returns the string of dta in hexadecimal format
     * @throws IOException : Throws exception if the source file does not exist
     */
    public static String GivemeHexStrind(Path p) throws IOException {
        byte[] byt = Files.readAllBytes(p);
        StringBuilder hexstr = new StringBuilder();
        for (byte b1 : byt) {
            hexstr.append(String.format("%02x", b1));
        }
        return hexstr.toString();

    }

    /**
     * function finds a decimal equivalent of a binary
     * @param bin : bin is the binary number in string format
     * @return returns an integer in decimal euqivalent to ethe binary string.
     */
    public static Integer givemeDecimalfromBinary(String bin)
    {
        int decimal =0;
        for(int i=0;i<bin.length();i++)
        {
            int j = Integer.parseInt(bin.substring(bin.length()-1-i,bin.length()-i));
            decimal += (int)Math.pow(2,i)*j;
        }
        return decimal;
    }

}