package com.ssafy.moneyandlove.chat.domain;

import java.time.LocalDateTime;

import org.bson.types.ObjectId;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

@Getter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Document(collection = "chat_message")
@CompoundIndex(name = "idx_room_id", def = "{'roomId': 1, '_id': -1}")
public class ChatMessage {

    @Id
	private ObjectId id;

    private Long roomId;
    private Long senderId;
    private String message;

	@CreatedDate
	private LocalDateTime createdAt;
}
