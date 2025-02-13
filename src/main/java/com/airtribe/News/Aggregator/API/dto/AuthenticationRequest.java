package com.airtribe.News.Aggregator.API.dto;

import lombok.*;
import org.hibernate.annotations.SecondaryRow;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Data
public class AuthenticationRequest {
    private String username;
    private String password;

}
