package com.ssafy.moneyandlove.chat.application;

import java.util.Optional;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import com.ssafy.moneyandlove.chat.domain.ChatRoom;
import com.ssafy.moneyandlove.chat.dto.ChatRoomIdResponse;
import com.ssafy.moneyandlove.chat.repository.ChatRoomRepository;
import com.ssafy.moneyandlove.common.error.ErrorType;
import com.ssafy.moneyandlove.common.exception.MoneyAndLoveException;
import com.ssafy.moneyandlove.user.domain.User;
import com.ssafy.moneyandlove.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class ChatRoomService {

    private final ChatRoomRepository chatRoomRepository;
    private final UserRepository userRepository;

    public ChatRoomIdResponse findChatRoom(Long userAId, Long userBId) {
        ChatRoom chatRoom = findByUsers(userAId, userBId)
            .orElseThrow(() -> new MoneyAndLoveException(ErrorType.CHATROOM_NOT_FOUND));
        return ChatRoomIdResponse.from(chatRoom);
    }

    public ChatRoomIdResponse getOrCreateChatRoom(Long userAId, Long userBId) {
        return findByUsers(userAId, userBId)
            .map(ChatRoomIdResponse::from)
            .orElseGet(() -> createChatRoom(userAId, userBId));
    }

    private Optional<ChatRoom> findByUsers(Long userAId, Long userBId) {
        Long user1Id = Math.min(userAId, userBId);
        Long user2Id = Math.max(userAId, userBId);
        return chatRoomRepository.findByUser1IdAndUser2Id(user1Id, user2Id);
    }

    private ChatRoomIdResponse createChatRoom(Long userAId, Long userBId) {
        User userA = userRepository.findById(userAId)
            .orElseThrow(() -> new MoneyAndLoveException(ErrorType.USER_NOT_FOUND));
        User userB = userRepository.findById(userBId)
            .orElseThrow(() -> new MoneyAndLoveException(ErrorType.USER_NOT_FOUND));

        try {
            ChatRoom chatRoom = chatRoomRepository.save(ChatRoom.of(userA, userB));
            return ChatRoomIdResponse.from(chatRoom);
        } catch (DataIntegrityViolationException e) {
            return findByUsers(userAId, userBId)
                .map(ChatRoomIdResponse::from)
                .orElseThrow(() -> new MoneyAndLoveException(ErrorType.CHATROOM_NOT_FOUND));
        }
    }
}
