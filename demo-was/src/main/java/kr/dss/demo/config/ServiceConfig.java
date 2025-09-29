package kr.dss.demo.config;

import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.File;
import java.io.IOException;

@Configuration
public class ServiceConfig {

    @Value("${dss.server.tsa.keystore.filename:}")
    private String ksFilename;

    @Value("${dss.server.tsa.keystore.type:}")
    private String ksType;

    @Value("${dss.server.tsa.keystore.password:}")
    private String ksPassword;

    @Value("${dss.server.tsa.alias:}")
    private String alias;

    @Value("${dss.server.tsa.password:}")
    private String keyEntryPassword;

    @Value("${dss.server.tsa.policy:}")
    private String tsaPolicy;

    @Bean
    public KeyEntityTSPSource tspSource() throws IOException {
        File ksFile = new ClassPathResource(ksFilename).getFile();

        KeyEntityTSPSource tspSource = new KeyEntityTSPSource(
                ksFile,
                ksType,
                ksPassword.toCharArray(),
                alias,
                keyEntryPassword.toCharArray()
        );

        tspSource.setTsaPolicy(tsaPolicy);
        return tspSource;
    }
}
