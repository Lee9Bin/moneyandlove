package com.ssafy.moneyandlove.common.config;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.server.support.DefaultHandshakeHandler;
import org.springframework.web.socket.sockjs.transport.handler.WebSocketTransportHandler;

import com.ssafy.moneyandlove.common.interceptor.StompAuthChannelInterceptor;
import com.ssafy.moneyandlove.common.resolver.LoginUserArgumentResolver;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
//웹소켓 활성화 어노테이션
@RequiredArgsConstructor
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

	private final LoginUserArgumentResolver loginUserArgumentResolver;
	private final StompAuthChannelInterceptor stompAuthChannelInterceptor;

	@Override
	public void configureMessageBroker(MessageBrokerRegistry config) {

		//클라이언트에서 메세지를 보낼 때 url에 붙여야할 preix
		config.setApplicationDestinationPrefixes("/api/chat");
		//클라이언트가 구독한 url
		config.enableSimpleBroker("/api/chat/receive");

	}


	@Override
	public void registerStompEndpoints(StompEndpointRegistry registry) {
		registry.addEndpoint("/api/websocket")
			.setAllowedOriginPatterns("*")
			.withSockJS()
			.setTransportHandlers(new WebSocketTransportHandler(new DefaultHandshakeHandler()));
	}

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		argumentResolvers.add(loginUserArgumentResolver);
	}

	@Override
	public void configureClientInboundChannel(ChannelRegistration registration) {
		registration.interceptors(stompAuthChannelInterceptor);
	}

}
