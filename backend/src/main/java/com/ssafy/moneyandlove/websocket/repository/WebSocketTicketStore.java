package com.ssafy.moneyandlove.websocket.repository;

import java.util.Optional;

public interface WebSocketTicketStore {

	void save(String ticket, Long userId);

	Optional<Long> consume(String ticket);
}
