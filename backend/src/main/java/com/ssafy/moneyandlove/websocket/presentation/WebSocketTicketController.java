package com.ssafy.moneyandlove.websocket.presentation;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ssafy.moneyandlove.common.annotation.LoginUser;
import com.ssafy.moneyandlove.user.domain.User;
import com.ssafy.moneyandlove.websocket.application.WebSocketTicketService;
import com.ssafy.moneyandlove.websocket.dto.WebSocketTicketResponse;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/ws")
@RequiredArgsConstructor
public class WebSocketTicketController {

	private final WebSocketTicketService ticketService;

	@PostMapping("/ticket")
	public ResponseEntity<WebSocketTicketResponse> issueTicket(@LoginUser User loginUser) {
		String ticket = ticketService.issue(loginUser.getId());
		return ResponseEntity.status(HttpStatus.CREATED)
			.body(WebSocketTicketResponse.of(ticket));
	}
}
