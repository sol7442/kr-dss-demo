package kr.dss.demo;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.TimestampDTO;
import eu.europa.esig.dss.ws.signature.common.TimestampTokenConverter;
import kr.dss.demo.config.MultipartResolverProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class WebAppUtils {
    private static final Logger LOG = LoggerFactory.getLogger(WebAppUtils.class);

    public static DSSDocument toDSSDocument(MultipartFile multipartFile) {
        try {
            if (multipartFile != null && !multipartFile.isEmpty()) {
                if (multipartFile.getSize() > MultipartResolverProvider.getInstance().getMaxFileSize()) {
                    throw new MaxUploadSizeExceededException(MultipartResolverProvider.getInstance().getMaxFileSize());
                }
                return new InMemoryDocument(multipartFile.getBytes(), multipartFile.getOriginalFilename());
            }
        } catch (IOException e) {
            LOG.error("Cannot read file : " + e.getMessage(), e);
        }
        return null;
    }

    public static List<DSSDocument> toDSSDocuments(List<MultipartFile> documentsToSign) {
        List<DSSDocument> dssDocuments = new ArrayList<>();
        if (Utils.isCollectionNotEmpty(documentsToSign)) {
            for (MultipartFile multipartFile : documentsToSign) {
                DSSDocument dssDocument = toDSSDocument(multipartFile);
                if (dssDocument != null) {
                    dssDocuments.add(dssDocument);
                }
            }
        }
        return dssDocuments;
    }

    public static TimestampToken toTimestampToken(TimestampDTO dto) {
        return TimestampTokenConverter.toTimestampToken(dto);
    }

    public static boolean isCollectionNotEmpty(List<MultipartFile> documents) {
        if (Utils.isCollectionNotEmpty(documents)) {
            for (MultipartFile multipartFile : documents) {
                if (multipartFile != null && !multipartFile.isEmpty()) {
                    // return true if at least one file is not empty
                    return true;
                }
            }
        }
        return false;
    }

    public static TimestampDTO fromTimestampToken(TimestampToken token) {
        return TimestampTokenConverter.toTimestampDTO(token);
    }
}
