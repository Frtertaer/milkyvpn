package homes.milky.vpn.kal2;

interface IKal2 {
    int start(String configJson);
    void stop();
    boolean isAlive();
}
