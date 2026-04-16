package com.ssafy.moneyandlove.websocket.dto;

public record WebSocketTicketResponse(String ticket) {

	public static WebSocketTicketResponse of(String ticket) {
		return new WebSocketTicketResponse(ticket);
	}
}
