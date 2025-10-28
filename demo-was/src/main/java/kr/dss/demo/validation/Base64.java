package kr.dss.demo.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Target({ElementType.METHOD,ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = Base64Validator.class)
@Documented
public @interface Base64 {

    String message() default "{error.digest.base64}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

}