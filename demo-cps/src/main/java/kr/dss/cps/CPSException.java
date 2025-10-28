package kr.dss.cps;

public class CPSException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 7127774975809178508L;

	public CPSException(String msg, Exception e) {
		super(msg,e);
	}

}
