package hellojpa;
import javax.persistence.*;
import javax.persistence.spi.PersistenceProviderResolverHolder;
import java.util.List;
import java.util.prefs.Preferences;

///import javax.persistence.EntityManager;

public class JpaMain {

    public static void main(String[] args){
        EntityManagerFactory emf= Persistence.createEntityManagerFactory("hello");
        EntityManager em=emf.createEntityManager();


        EntityTransaction  tx= em.getTransaction();
        try{
            tx.begin();
            logic(em);
            tx.commit();
        }catch (Exception e){
            tx.rollback();
        }finally {
            em.close();
        }
        emf.close();

    }
    private static  void logic (EntityManager em){
       /*
        String id="id1";
        hellojpa.Member member = new hellojpa.Member();
        member.setId(id);
        member.setUsername("user3");
        member.setAge(20);

        // 등록
        em.persist(member);

        //한건 조회
        hellojpa.Member findMember=em.find(hellojpa.Member.class,id);
        System.out.println("findMember = "+findMember.getUsername()+",age = "+findMember.getAge());

        //수정 - 수정후 따로 저장안해도 됌.
        findMember.setAge(22);
*/

        //목록 조회
        // 멤버(member) 객체를 대상으로 커리를 처리==멤버 객체 다가져와
        // 대상이 테이블이 아니고 객체가 되는 것 이다.
        List<Member> members= em.createQuery("select m from Member m", Member.class).getResultList(); // 결과를 보면 실제 사용된 커리는 select하고 필드를 나열.
        System.out.println("members.size = "+members.size());
        for(Member mem : members){
            System.out.println("member.name = "+mem.getUsername());
        }

        //삭제
        // em.remove(member);

    }
}
