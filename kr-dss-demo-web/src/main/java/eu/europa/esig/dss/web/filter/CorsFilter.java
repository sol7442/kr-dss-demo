package eu.europa.esig.dss.web.filter;


import eu.europa.esig.dss.web.controller.KR_SignatureController;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.IOException;


public class CorsFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(CorsFilter.class);

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods","GET, POST, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers","*");

        LOG.debug("{} -> {}",req,res);
        chain.doFilter(req, res);
    }
}
