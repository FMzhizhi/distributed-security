import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class springboot {

    @Test
    public void testt(){

        String hashpw = BCrypt.hashpw("secret", BCrypt.gensalt());
        System.out.println(hashpw);
        boolean checkpw = BCrypt.checkpw("123", hashpw);
        System.out.println(checkpw);
    }

    @Test
    public void test1111(){
        String secret = new BCryptPasswordEncoder().encode("secret");
        boolean checkpw = BCrypt.checkpw("secret", "$2a$10$1ORNUgzn4iAsBfhYf/ui8uNeMosbWNZpdQKIDwK0pEj60DlMBtcqG");
        System.out.println(secret);
        System.out.println(checkpw);
    }
}
