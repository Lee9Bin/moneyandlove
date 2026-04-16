package com.ssafy.moneyandlove.websocket.application;

import java.util.UUID;

import org.springframework.stereotype.Service;

import com.ssafy.moneyandlove.websocket.repository.WebSocketTicketStore;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class WebSocketTicketService {

	private final WebSocketTicketStore ticketStore;

	public String issue(Long userId) {
		String ticket = UUID.randomUUID().toString();
		ticketStore.save(ticket, userId);
		return ticket;
	}
}
