package com.thirdparty.scan;

import java.math.BigDecimal;

public class DemicalConverter {
	
	public static String convertToString(BigDecimal bDecimal){
		String convertedStr = "";
		try{
			convertedStr = bDecimal.toString();
			return convertedStr;
		}catch(Exception e){
			convertedStr="";
			return convertedStr;
		}
		
	}
	
	public static BigDecimal convertToBigDecimal(String str){
		BigDecimal bigDecimal = new BigDecimal("0.0");
		try{
			bigDecimal = new BigDecimal(str);
			return bigDecimal;
		}catch(Exception e){
			return null;
		}		
	}	
}
