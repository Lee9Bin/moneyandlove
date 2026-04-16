package com.ssafy.moneyandlove.common.resolver;

import java.util.Map;

import org.springframework.core.MethodParameter;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.ModelAndViewContainer;

import com.ssafy.moneyandlove.common.annotation.LoginUser;
import com.ssafy.moneyandlove.common.error.ErrorType;
import com.ssafy.moneyandlove.common.exception.MoneyAndLoveException;
import com.ssafy.moneyandlove.common.interceptor.WebSocketTicketHandshakeInterceptor;
import com.ssafy.moneyandlove.user.domain.User;
import com.ssafy.moneyandlove.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class LoginUserArgumentResolver implements org.springframework.web.method.support.HandlerMethodArgumentResolver,
	org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver {

	private final UserRepository userRepository;

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return parameter.hasParameterAnnotation(LoginUser.class)
			&& User.class.isAssignableFrom(parameter.getParameterType());
	}

	// HTTP (REST API)
	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
		NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
		//SecurityContext에서 값 꺼내기
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return authentication.getPrincipal();
	}

	// WebSocket (STOMP @MessageMapping)
	@Override
	public Object resolveArgument(MethodParameter parameter, Message<?> message) {
		StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message);
		Long userId = extractUserId(accessor);
		return userRepository.findById(userId)
			.orElseThrow(() -> new MoneyAndLoveException(ErrorType.USER_NOT_FOUND));
	}

	private Long extractUserId(StompHeaderAccessor accessor) {
		Map<String, Object> sessionAttrs = accessor.getSessionAttributes();
		if (sessionAttrs == null) {
			throw new MoneyAndLoveException(ErrorType.TOKEN_NOT_EXIST);
		}
		Object value = sessionAttrs.get(WebSocketTicketHandshakeInterceptor.USER_ID_ATTR);
		if (value == null) {
			throw new MoneyAndLoveException(ErrorType.TOKEN_NOT_EXIST);
		}
		return ((Number) value).longValue();
	}
}
