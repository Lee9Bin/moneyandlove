package com.ssafy.moneyandlove.common.interceptor;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.ssafy.moneyandlove.common.error.ErrorType;
import com.ssafy.moneyandlove.common.exception.MoneyAndLoveException;
import com.ssafy.moneyandlove.common.jwt.JwtProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
@RequiredArgsConstructor
public class StompAuthChannelInterceptor implements ChannelInterceptor {

	private static final String HEADER_AUTHORIZATION = "Authorization";
	private static final String TOKEN_PREFIX = "Bearer ";

	private final JwtProvider jwtProvider;

	@Override
	public Message<?> preSend(Message<?> message, MessageChannel channel) {
		StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

		if (accessor == null) {
			return message;
		}

		if (StompCommand.CONNECT.equals(accessor.getCommand())) {
			String authHeader = accessor.getFirstNativeHeader(HEADER_AUTHORIZATION);

			if (authHeader == null || !authHeader.startsWith(TOKEN_PREFIX)) {
				log.warn("STOMP CONNECT 인증 실패: Authorization 헤더 없음");
				throw new MoneyAndLoveException(ErrorType.TOKEN_NOT_EXIST);
			}

			String token = authHeader.substring(TOKEN_PREFIX.length());
			jwtProvider.validateToken(token);
			Authentication authentication = jwtProvider.getAuthentication(token);
			accessor.setUser(authentication);
		}

		return message;
	}
}
