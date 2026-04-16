package com.ssafy.moneyandlove.common.interceptor;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;
import org.springframework.web.util.UriComponentsBuilder;

import com.ssafy.moneyandlove.websocket.repository.RedisWebSocketTicketStore;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class WebSocketTicketHandshakeInterceptor implements HandshakeInterceptor {

	public static final String TICKET_PARAM = "ticket";
	public static final String USER_ID_ATTR = "userId";

	private final RedisWebSocketTicketStore ticketStore;

	@Override
	public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Map<String, Object> attributes) {
		String ticket = extractTicket(request.getURI());
		if (ticket == null || ticket.isBlank()) {
			return reject(response, "ticket missing");
		}

		Optional<Long> userId = ticketStore.consume(ticket);
		if (userId.isEmpty()) {
			return reject(response, "ticket invalid or expired");
		}

		attributes.put(USER_ID_ATTR, userId.get());
		return true;
	}

	@Override
	public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Exception exception) {

	}

	private String extractTicket(URI uri) {
		return UriComponentsBuilder.fromUri(uri)
			.build()
			.getQueryParams()
			.getFirst(TICKET_PARAM);
	}

	private boolean reject(ServerHttpResponse response, String reason) {
		response.setStatusCode(HttpStatus.UNAUTHORIZED);
		log.warn("WebSocket handshake rejected: {}", reason);
		return false;
	}
}
