package com.airtribe.News.Aggregator.API.service;

import com.airtribe.News.Aggregator.API.entity.User;
import com.airtribe.News.Aggregator.API.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class NewsService {
    @Autowired
    private UserRepository userRepository;

    public void markAsRead(String username, String articleId){
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.getReadArticles().add(articleId);
        userRepository.save(user);
    }
    public void markAsFavorite(String username, String articleId){
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.getFavoriteArticles().add(articleId);
        userRepository.save(user);
    }

    public Set<String> getReadArticles(String username){
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return user.getReadArticles();
    }
    public Set<String> getFavoriteArticles(String username){
        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->new RuntimeException("User not find"));
        return user.getFavoriteArticles();
    }
}
