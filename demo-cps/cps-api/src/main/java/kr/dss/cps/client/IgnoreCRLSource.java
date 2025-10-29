package kr.dss.cps.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;

public class IgnoreCRLSource implements CRLSource  {
    /**
	 * 
	 */
	private static final long serialVersionUID = 5788543007351938753L;
	private static final Logger LOG = LoggerFactory.getLogger(IgnoreCRLSource.class);

	@Override
	public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("IgnoreCRLSource: skipping CRL lookup for {}", certificateToken.getAbbreviation());
        }		return null;
	}

}
