import React, {
  useState,
  useEffect,
  useRef,
  FormEvent,
  useCallback,
} from "react";
import {
  OpenVidu,
  Session,
  Publisher,
  StreamManager,
  Device,
} from "openvidu-browser";
import useSessionHandlers from "../../hooks/useSessionHandlers";
import JoinSessionForm from "../../components/room/JoinSessionForm";
import GameView from "../../components/room/GameView";
import { createSession, createToken } from "../../utils/api";
import { useRecoilValue } from "recoil";
import { maxExpressionState, userToken } from "../../atom/store";
import mainBg from "../../assets/main_bg.png";
import { useLocation } from "react-router-dom";
import { updateGamePoints } from "../../utils/updateGamePoints";

// Room 컴포넌트
const Room: React.FC = () => {
  //recoil 전역변수
  const maxExpression = useRecoilValue(maxExpressionState);
  const token = useRecoilValue(userToken);

  //감정을 이모지로 변환
  const expressionToEmoji = (expression: string): string => {
    const emojis: { [key: string]: string } = {
      happy: "😊",
      sad: "😢",
      angry: "😡",
      fearful: "😨",
      disgusted: "🤢",
      surprised: "😲",
      neutral: "😐",
    };
    return emojis[expression] || "😐";
  };
  // 상태 변수 설정

  const [isModalOpen, setIsModalOpen] = useState(true);
  const [mode, setMode] = useState<string>("chat");
  const [mySessionId, setMySessionId] = useState<string>("");
  const [myUserName, setMyUserName] = useState<string>("");
  const [session, setSession] = useState<Session | undefined>();
  const [mainStreamManager, setMainStreamManager] = useState<
    StreamManager | undefined
  >();
  const [publisher, setPublisher] = useState<Publisher | undefined>();
  const [subscriber, setSubscriber] = useState<StreamManager | undefined>();
  const [messages, setMessages] = useState<
    { user: string; text: string; Emoji: string }[]
  >([]);
  const [newMessage, setNewMessage] = useState<string>("");
  const currentVideoDevice = useRef<Device | undefined>();

  // 세션 핸들러 설정
  const deleteSubscriber = useSessionHandlers(
    session,
    setSubscriber,
    setMessages
  );

  //matching 성공 시
  const location = useLocation();
  const matchData = location.state?.matchData;
  useEffect(() => {
    if (matchData) {
      setMyUserName(matchData.fromUser.nickname);
      setMySessionId(matchData.sessionId);
    }
  }, [matchData]);

  useEffect(() => {
    if (myUserName && mySessionId) {
      joinSession();
    }
  }, [myUserName, mySessionId]);

  console.log("매치데이터", matchData);

  // 페이지를 떠날 때 세션 종료
  useEffect(() => {
    const handleBeforeUnload = () => leaveSession();
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [session]);

  // 포인트 차감 함수
  const deductPoints = async () => {
    if (token) {
      try {
        await updateGamePoints({ gamePoint: -100, token });
        console.log("매칭으로 인한 포인트 차감 성공");
      } catch (error) {
        console.error("매칭으로 인한 포인트 차감 실패", error);
      }
    }
  };

  // 메인 비디오 스트림 설정 핸들러
  // const handleMainVideoStream = (stream: StreamManager) => {
  //   setMainStreamManager((prev) => (prev !== stream ? stream : prev));
  // };

  // 토큰 얻기 함수
  const getToken = useCallback(async (): Promise<string> => {
    const sessionId = await createSession(mySessionId, token ? token : "");
    return await createToken(sessionId, token ? token : "");
  }, [mySessionId]);

  // 세션 참가 함수
  const joinSession = async () => {
    const OV = new OpenVidu();
    const session = OV.initSession();

    setSession(session);

    try {
      const token = await getToken();
      console.log("토큰", token);
      await session.connect(token, { clientData: myUserName });
      const devices = await OV.getDevices();
      console.log(devices + " :::::devices");
      const videoDevices = devices.filter((device) => {
        console.log(device + " :::::::device");
        return device.kind === "videoinput"; // 이 부분도 return을 추가하여 올바르게 필터링되도록 수정
      });
      console.log("비디오디바이스", videoDevices);
      // 첫 번째 사용 가능한 비디오 장치 선택
      const selectedDevice = videoDevices.length > 0 ? videoDevices[0] : null;
      const videoSource = selectedDevice ? selectedDevice.deviceId : undefined;

      const publisher = await OV.initPublisherAsync(undefined, {
        audioSource: undefined,
        videoSource: videoSource,
        publishAudio: true,
        publishVideo: true,
        resolution: "640x480",
        frameRate: 60,
        insertMode: "APPEND",
        mirror: true,
      });

      session.publish(publisher);

      const currentVideoDeviceId = publisher.stream
        .getMediaStream()
        .getVideoTracks()[0]
        .getSettings().deviceId;
      currentVideoDevice.current = videoDevices.find(
        (device) => device.deviceId === currentVideoDeviceId
      );
      console.log(publisher);
      setPublisher(publisher);
      setMainStreamManager(publisher);

      // 세션 연결 및 퍼블리셔 설정이 성공적으로 완료된 후 포인트 차감
      deductPoints();
    } catch (error) {
      const typedError = error as { code: string; message: string }; // 오류 타입 명시
      console.error(
        "There was an error connecting to the session:",
        typedError.code,
        typedError.message
      );
    }
  };

  // 세션 떠나기 함수
  const leaveSession = () => {
    if (session) session.disconnect();
    setSession(undefined);
    setSubscriber(undefined);
    setMySessionId("");
    setMyUserName("");
    setMainStreamManager(undefined);
    setPublisher(undefined);
  };

  // 메시지 전송 함수
  const sendMessage = () => {
    if (
      session &&
      newMessage.trim() &&
      expressionToEmoji(maxExpression).trim()
    ) {
      session.signal({
        data: JSON.stringify({
          user: myUserName,
          text: newMessage,
          Emoji: expressionToEmoji(maxExpression),
        }),
        to: [],
        type: "chat",
      });
      setNewMessage("");
    }
  };

  return (
    <div className="relative min-h-screen">
      <img
        src={mainBg}
        alt=""
        className={`absolute inset-0 -z-10 h-screen w-screen bg-cover bg-center`}
      />
      <div className="absolute inset-0 -z-10 bg-black opacity-40"></div>

      <GameView
        mode={mode}
        setMode={setMode}
        mainStreamManager={mainStreamManager}
        subscriber={subscriber}
        messages={messages}
        newMessage={newMessage}
        setNewMessage={setNewMessage}
        sendMessage={sendMessage}
        leaveSession={leaveSession}
        isModalOpen={isModalOpen}
        setIsModalOpen={setIsModalOpen}
        myUserName={myUserName}
        session={session}
        matchData={matchData}
      />
    </div>
  );
};

export default Room;
