package demo.settings.exceptions;

import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public interface ExceptionAttributes {

    Map<String, Object> getExceptionAttributes(Exception exception,
                                               HttpServletRequest httpRequest, HttpStatus httpStatus);

}