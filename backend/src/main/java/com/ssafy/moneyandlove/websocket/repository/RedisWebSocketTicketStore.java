package com.ssafy.moneyandlove.websocket.repository;

import java.time.Duration;
import java.util.Optional;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class RedisWebSocketTicketStore implements WebSocketTicketStore {

	private static final String KEY_PREFIX = "ws:ticket:";
	private static final Duration TTL = Duration.ofSeconds(30);

	private final RedisTemplate<String, Object> redisTemplate;

	@Override
	public void save(String ticket, Long userId) {
		redisTemplate.opsForValue().set(buildKey(ticket), userId, TTL);
	}

	@Override
	public Optional<Long> consume(String ticket) {
		Object value = redisTemplate.opsForValue().getAndDelete(buildKey(ticket));
		if (value == null) {
			return Optional.empty();
		}
		return Optional.of(((Number)value).longValue());
	}

	private String buildKey(String ticket) {
		return KEY_PREFIX + ticket;
	}
}
