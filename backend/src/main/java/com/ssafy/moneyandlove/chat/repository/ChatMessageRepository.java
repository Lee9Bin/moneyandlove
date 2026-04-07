package com.ssafy.moneyandlove.chat.repository;

import java.util.List;

import org.bson.types.ObjectId;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;

import com.ssafy.moneyandlove.chat.domain.ChatMessage;

public interface ChatMessageRepository extends MongoRepository<ChatMessage, ObjectId> {

    List<ChatMessage> findByRoomIdOrderByIdDesc(Long roomId, Pageable pageable);

    List<ChatMessage> findByRoomIdAndIdLessThanOrderByIdDesc(Long roomId, ObjectId cursor, Pageable pageable);
}
