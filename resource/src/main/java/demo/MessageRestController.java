package demo;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController

public class MessageRestController {

    @RequestMapping("/message")
    @Secured("ROLE_ADMIN")
    public Message getMessage() {
        return new Message("Hello Custom Message");
    }

    private class Message {
        private String id = UUID.randomUUID().toString();
        private String content;

        Message(String content) {
            this.content = content;
        }

        public String getId() {
            return id;
        }

        public String getContent() {
            return content;
        }
    }

}

