package broker

type Broker[T any] struct {
	topics      map[string]chan T
	maxSizeChan uint
}

func New[T any](maxCountMsgInTopic uint) *Broker[T] {
	return &Broker[T]{
		topics:      make(map[string]chan T),
		maxSizeChan: maxCountMsgInTopic,
	}
}

func (b *Broker[T]) Publish(topic string, msg T) {
	if v, ok := b.topics[topic]; ok {
		v <- msg
		return
	}

	b.topics[topic] = make(chan T, b.maxSizeChan)
	b.topics[topic] <- msg
}

func (b *Broker[T]) CloseTopic(topic string) {
	if v, ok := b.topics[topic]; ok {
		close(v)
	}

	delete(b.topics, topic)
}

func (b *Broker[T]) Subscribe(topic string) chan T {
	if _, ok := b.topics[topic]; !ok {
		b.topics[topic] = make(chan T, b.maxSizeChan)
	}

	return b.topics[topic]
}
