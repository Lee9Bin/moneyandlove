package com.ssafy.moneyandlove.chat.domain;

import com.ssafy.moneyandlove.common.TimeBaseEntity;
import com.ssafy.moneyandlove.user.domain.User;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Entity
@Getter
@Table(uniqueConstraints = @UniqueConstraint(columnNames = {"user1_id", "user2_id"}))
@SuperBuilder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ChatRoom extends TimeBaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user1_id")
	private User user1;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user2_id")
	private User user2;

	public ChatRoom(User user1, User user2) {
		this.user1 = user1;
		this.user2 = user2;
	}

	public static ChatRoom of(User userA, User userB) {
		if (userA.getId() < userB.getId()) {
			return new ChatRoom(userA, userB);
		}
		return new ChatRoom(userB, userA);
	}
}
