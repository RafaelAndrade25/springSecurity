package tech.RaffProj.springSecurity.controller.dto;

public record FeedItemDto(long tweetId,
                          String content,
                          String username) {
}
