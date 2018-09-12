package com.thirdparty;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.Test;

public class TestSonaTypeParser {


	 @Test
	    public void testMain() {
		 boolean nullOccured = false;
		 try {
	        ScanGenerator.main(new String[] {"fixed" ,"E:\\sample.zip"});
		 }
		 catch(NullPointerException ne) {
			 
				 nullOccured = true;
			}
		 catch(Exception e) {
	        fail("Other than Null Pointer exception thrown"+e.getMessage());
		 }  
	     assertTrue(nullOccured,"Expected NullPointerException. But no expection occured");   
	              
	         
	    }
}
