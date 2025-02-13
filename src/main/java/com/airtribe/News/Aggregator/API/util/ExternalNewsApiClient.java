package com.airtribe.News.Aggregator.API.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Set;

@Component
public class ExternalNewsApiClient {
    @Value("${gnews.api.key}")
    private String apiKey;

    private final WebClient webClient;

    public ExternalNewsApiClient(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("https://gnews.io/api/v4").build();
    }

    public Mono<String> fetchNews(Set<String> preferences){
        if(preferences == null || preferences.isEmpty()){
            return Mono.just("{}");
        }
        String query = String.join(" OR ", preferences);

        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/search")
                        .queryParam("q", query)
                        .queryParam("lang","en")
                        .queryParam("max","10")
                        .queryParam("country","in")
                        .queryParam("apikey", apiKey)
                        .build())
                .retrieve()
                .bodyToMono(String.class)
                .onErrorResume(e -> Mono.just("{\"error\": \"" + e.getMessage() + "\"}")); // Handle errors;
    }

    public Mono<String> searchNews(String keyword){
        if(keyword == null || keyword.isEmpty()){
            return Mono.just("{}");
        }
        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/search")
                        .queryParam("q", keyword)
                        .queryParam("apikey", apiKey) // GNews uses "token" for API key
                        .queryParam("lang", "en") // Optional: Filter by language
                        .queryParam("max", "10") // Optional: Limit the number of results
                        .queryParam("country","in")
                        .build())
                .retrieve()
                .bodyToMono(String.class)
                .onErrorResume(e -> Mono.just("{\"error\": \"" + e.getMessage() + "\"}")); // Handle errors; // Parse the response as a String (JSON)

    }
}
