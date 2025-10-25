package tech.RaffProj.springSecurity.controller.dto;

public record LoginResponse(String accessToken, Long expiresIn) {
}
