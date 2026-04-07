package com.ssafy.moneyandlove.chat.application;

import java.util.List;

import org.bson.types.ObjectId;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.ssafy.moneyandlove.chat.domain.ChatMessage;
import com.ssafy.moneyandlove.chat.dto.ChatMessageRequest;
import com.ssafy.moneyandlove.chat.dto.ChatMessageResponse;
import com.ssafy.moneyandlove.chat.repository.ChatMessageRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class ChatMessageService {

	private final ChatMessageRepository chatMessageRepository;

	public ChatMessageResponse save(Long senderId ,ChatMessageRequest chatMessageRequest) {
		ChatMessage chatMessage = chatMessageRepository.save(chatMessageRequest.toChatMessage(senderId));
		return ChatMessageResponse.from(chatMessage);
	}

	public List<ChatMessageResponse> getMessages(Long roomId, String cursor, int size) {
		List<ChatMessage> messages;

		if (cursor == null || cursor.isBlank()) {
			messages = chatMessageRepository.findByRoomIdOrderByIdDesc(roomId, PageRequest.of(0, size));
		}
		else {
			messages = chatMessageRepository.findByRoomIdAndIdLessThanOrderByIdDesc(roomId, new ObjectId(cursor), PageRequest.of(0, size));
		}

		return messages.stream()
			.map(ChatMessageResponse::from)
			.toList();
	}
}
