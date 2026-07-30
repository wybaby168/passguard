package dev.flyfish.passguard.crypto.jpa;

import dev.flyfish.passguard.crypto.AnnotatedFieldProcessor;
import org.hibernate.boot.Metadata;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.event.spi.PreInsertEvent;
import org.hibernate.event.spi.PreInsertEventListener;
import org.hibernate.event.spi.PreLoadEvent;
import org.hibernate.event.spi.PreLoadEventListener;
import org.hibernate.event.spi.PreUpdateEvent;
import org.hibernate.event.spi.PreUpdateEventListener;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;

import java.util.Objects;

/**
 * Hibernate 5 事件集成器。
 *
 * <p>加密仅修改 Hibernate 将要交给 JDBC 的 state，读取时则在实体赋值与
 * 脏检查快照建立前解密 state。它不会把调用方实体遗留为密文。</p>
 */
public final class PassGuardHibernate5Integrator implements Integrator {
    private final Listener listener;

    /**
     * @param processor 共享字段处理器
     */
    public PassGuardHibernate5Integrator(AnnotatedFieldProcessor processor) {
        this.listener = new Listener(Objects.requireNonNull(processor, "processor"));
    }

    @Override
    public void integrate(
            Metadata metadata,
            SessionFactoryImplementor sessionFactory,
            SessionFactoryServiceRegistry serviceRegistry) {
        EventListenerRegistry events =
                serviceRegistry.getService(EventListenerRegistry.class);
        events.prependListeners(EventType.PRE_LOAD, listener);
        events.appendListeners(EventType.PRE_INSERT, listener);
        events.appendListeners(EventType.PRE_UPDATE, listener);
    }

    @Override
    public void disintegrate(
            SessionFactoryImplementor sessionFactory,
            SessionFactoryServiceRegistry serviceRegistry) {
        // EventListenerRegistry 与 SessionFactory 同生命周期，无需手工注销。
    }

    private static final class Listener implements
            PreLoadEventListener, PreInsertEventListener, PreUpdateEventListener {
        private static final long serialVersionUID = 1L;
        private final AnnotatedFieldProcessor processor;

        private Listener(AnnotatedFieldProcessor processor) {
            this.processor = processor;
        }

        @Override
        public void onPreLoad(PreLoadEvent event) {
            processor.decryptStateAfterRead(
                    event.getEntity().getClass(),
                    event.getPersister().getPropertyNames(),
                    event.getState());
        }

        @Override
        public boolean onPreInsert(PreInsertEvent event) {
            processor.encryptStateForWrite(
                    event.getEntity(),
                    event.getPersister().getPropertyNames(),
                    event.getState());
            return false;
        }

        @Override
        public boolean onPreUpdate(PreUpdateEvent event) {
            processor.encryptStateForWrite(
                    event.getEntity(),
                    event.getPersister().getPropertyNames(),
                    event.getState());
            return false;
        }
    }
}
