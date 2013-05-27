package com.blue.pcap.util;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.mina.filter.firewall.Subnet;

public class StringUtil {
	public final static String NUL = "\0";

	public static char byte2ASCII(byte b) {
		return (char) b;
	}

	public static char[] Byte2ASCII(byte[] bs) {
		char[] cs = new char[bs.length];
		for (int i = 0, ilen = bs.length; i < ilen; i++) {
			cs[i] = byte2ASCII(bs[i]);
		}
		return cs;
	}

	public static String byte2Hex(int b) {
		return byte2Hex((byte) b);
	}

	public static String byte2Hex(byte b) {
		String s = Integer.toHexString(b).toUpperCase();
		int len = s.length();
		s = len == 1 ? "0" + s : s.substring(len - 2, len);
		return s;
	}

	public static String[] byte2Hex(byte[] bs) {
		String[] ss = new String[bs.length];
		for (int i = 0, ilen = bs.length; i < ilen; i++) {
			ss[i] = byte2Hex(bs[i]);
		}
		return ss;
	}

	public static String byte2HexString(byte[] bs) {
		return join(byte2Hex(bs), " ");
	}

	public static byte[] stringToHex(String s) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		String[] ss = null;
		if (s.indexOf(" ") > 0) {
			ss = s.split(" ");
		} else {
			int ilen = s.length() / 2;
			ss = new String[ilen];
			for (int i = 0; i < ilen; i++) {
				ss[i] = s.substring(i * 2, (i + 1) * 2);
			}
		}

		for (int i = 0, ilen = ss.length; i < ilen; i++) {
			bos.write(Integer.decode("0x" + ss[i]).intValue());
		}
		return bos.toByteArray();
	}

	public static byte[] fillLength(String s, int length) {
		byte[] bs = new byte[length];
		byte[] sbs = s.getBytes();

		for (int i = 0; i < length; i++)
			bs[i] = (i < sbs.length) ? sbs[i] : 0;

		return bs;
	}

	public static String md5Digest(String plainText) throws NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(plainText.getBytes());
		byte b[] = md.digest();

		int i;

		StringBuffer buf = new StringBuffer("");
		for (int offset = 0; offset < b.length; offset++) {
			i = b[offset];
			if (i < 0)
				i += 256;
			if (i < 16)
				buf.append("0");
			buf.append(Integer.toHexString(i));
		}

		return buf.toString();
	}

	public static String join(Object[] ss, String split) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0, ilen = ss.length; i < ilen; i++) {
			sb.append(ss[i]);
			if (i < ilen - 1)
				sb.append(split);
		}
		return sb.toString();
	}

	public static String join(String[] ss, String split) {
		return join((Object[]) ss, split);
	}

	/**
	 * @param str
	 * @return 字符串是否为空
	 */
	public static boolean isEmpty(String str) {
		return str == null || str.length() == 0;
	}

	public static Subnet parseSubnetStr(String ip) throws UnknownHostException {
		String[] blockedSubnet = ip.split("/");
		InetAddress address = InetAddress.getByName(blockedSubnet[0]);
		int mask = Integer.parseInt(blockedSubnet[1]);
		return new Subnet(address, mask);
	}
}
