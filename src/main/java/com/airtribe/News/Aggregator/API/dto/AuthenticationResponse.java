package com.airtribe.News.Aggregator.API.dto;

import lombok.*;

import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Data
public class AuthenticationResponse {
    private String jwt;
    private Date expirationTime;
    public AuthenticationResponse(String jwt) {
        this.jwt = jwt;
    }
}
